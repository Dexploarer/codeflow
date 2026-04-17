const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const { analyzeFiles } = require('./analyzer');
const { fetchRepoFiles } = require('./github-client');
const { JobStore } = require('./job-store');
const AgentContract = require('./agent-contract');
const ReportCore = require('../shared/report-core');

const DEFAULT_PORT = Number(process.env.PORT || 8787);
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 60;
const MAX_REQUEST_BODY_SIZE = 5 * 1024 * 1024;
const ANALYZE_GITHUB_DEFAULT_MAX_FILES = 200;
const ANALYZE_GITHUB_HARD_MAX_FILES = 300;
const ANALYZE_GITHUB_DEFAULT_MAX_FILE_BYTES = 120000;
const ANALYZE_GITHUB_HARD_MAX_FILE_BYTES = 200000;

const jobStore = new JobStore();
const requestBuckets = new Map();

function idempotencyKeyFromRequest(req, body){
  const headerValue = req.headers['idempotency-key'];
  if (typeof headerValue === 'string' && headerValue.trim()) return headerValue.trim().slice(0, 256);
  if (body && typeof body.idempotencyKey === 'string' && body.idempotencyKey.trim()) return body.idempotencyKey.trim().slice(0, 256);
  return '';
}

function requestIdFrom(req){
  const header = req.headers['x-request-id'];
  if (typeof header === 'string' && header.trim()) return header.trim().slice(0, 128);
  return crypto.randomUUID();
}

function parseAuthHeader(req){
  const header = req.headers.authorization;
  if (typeof header !== 'string') return '';
  const parts = header.split(' ');
  if (parts.length === 2 && /^bearer$/i.test(parts[0])) return parts[1].trim();
  return '';
}

function requiredTokenForScope(scope){
  if (scope === 'admin') return process.env.CODEFLOW_API_ADMIN_TOKEN || '';
  return process.env.CODEFLOW_API_READ_TOKEN || '';
}

function hasScope(req, scope){
  const required = requiredTokenForScope(scope);
  if (!required) return true;
  return parseAuthHeader(req) === required;
}

function signedJobToken(jobId){
  const secret = process.env.CODEFLOW_JOB_TOKEN_SECRET || '';
  if (!secret) return null;
  const sig = crypto.createHmac('sha256', secret).update(String(jobId)).digest('hex');
  return `${jobId}.${sig}`;
}

function validateJobAccessToken(jobId, req, url){
  const secret = process.env.CODEFLOW_JOB_TOKEN_SECRET || '';
  if (!secret) return true;
  const fromHeader = req.headers['x-job-token'];
  const token = typeof fromHeader === 'string' && fromHeader.length ? fromHeader : url.searchParams.get('accessToken');
  if (!token) return false;
  return token === signedJobToken(jobId);
}

function jobIdFromPath(pathname){
  const parts = pathname.split('/');
  if (parts[3] === 'jobs') return parts[4] || '';
  if (parts[3] === 'agent') return parts[4] || '';
  return '';
}

function sendJson(res, statusCode, data){
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function sendV2(res, statusCode, options = {}){
  const payload = {
    meta: {
      requestId: options.requestId || null,
      schemaVersion: ReportCore.SCHEMA_VERSION,
      jobId: options.jobId || null,
      cacheKey: options.cacheKey || null,
      pageInfo: options.pageInfo || null,
      analysisWarnings: options.analysisWarnings || []
    },
    data: options.data === undefined ? null : options.data,
    errors: options.errors || []
  };
  sendJson(res, statusCode, payload);
}

function parseBody(req){
  return new Promise((resolve, reject) => {
    let data = '';
    let finished = false;
    req.on('data', (chunk) => {
      if (finished) return;
      data += chunk;
      if (data.length > MAX_REQUEST_BODY_SIZE) {
        finished = true;
        reject(Object.assign(new Error('Payload too large'), { statusCode: 413, code: 'PAYLOAD_TOO_LARGE' }));
        req.destroy();
        return;
      }
    });
    req.on('end', () => {
      if (finished) return;
      finished = true;
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (parseError) {
        reject(Object.assign(new Error('Invalid JSON body'), { statusCode: 400, code: 'INVALID_JSON' }));
      }
    });
    req.on('error', (err) => {
      if (finished) return;
      finished = true;
      reject(err);
    });
  });
}

function clientKey(req){
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function enforceRateLimit(req, res, requestId){
  const now = Date.now();
  const key = clientKey(req);
  const bucket = requestBuckets.get(key) || { resetAt: now + RATE_LIMIT_WINDOW_MS, count: 0 };
  if (now > bucket.resetAt) {
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
    bucket.count = 0;
  }
  bucket.count += 1;
  requestBuckets.set(key, bucket);
  if (bucket.count > RATE_LIMIT_MAX) {
    if (req.url && req.url.startsWith('/api/v2/')) {
      sendV2(res, 429, {
        requestId,
        errors: [{
          code: 'RATE_LIMITED',
          message: 'Rate limit exceeded',
          details: {
            detail: `Allowed ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW_MS / 1000}s window.`
          }
        }]
      });
    } else {
      sendJson(res, 429, {
        error: 'Rate limit exceeded',
        detail: `Allowed ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW_MS / 1000}s window.`
      });
    }
    return false;
  }
  return true;
}

function deriveSnapshotWarnings(files, maxFiles, maxFileBytes){
  const warnings = [];
  if (files.length > maxFiles) {
    warnings.push({
      code: 'MAX_FILES_EXCEEDED',
      message: `Input had ${files.length} files; only first ${maxFiles} were analyzed.`,
      details: { received: files.length, analyzed: maxFiles }
    });
  }
  let truncated = 0;
  files.slice(0, maxFiles).forEach((file) => {
    if (String(file.content || '').length > maxFileBytes) truncated += 1;
  });
  if (truncated > 0) {
    warnings.push({
      code: 'MAX_FILE_BYTES_TRUNCATION',
      message: `${truncated} files were truncated to ${maxFileBytes} bytes.`,
      details: { truncatedFiles: truncated, maxFileBytes }
    });
  }
  return warnings;
}

function normalizeRunResult(result){
  return {
    rawReport: result.rawReport,
    analysisWarnings: result.analysisWarnings || [],
    sourceMeta: result.sourceMeta || {}
  };
}

async function runAnalysis(input){
  if (!input || typeof input !== 'object') {
    throw Object.assign(new Error('input object is required'), { statusCode: 400, code: 'INVALID_INPUT' });
  }

  if (input.kind === 'codeflow-report') {
    if (!input.report || typeof input.report !== 'object') {
      throw Object.assign(new Error('input.report is required for kind=codeflow-report'), { statusCode: 400, code: 'INVALID_INPUT' });
    }
    return normalizeRunResult({
      rawReport: input.report,
      analysisWarnings: [],
      sourceMeta: {
        totalFiles: input.report.summary && input.report.summary.totalFiles ? input.report.summary.totalFiles : (input.report.files || []).length,
        analyzedFiles: (input.report.files || []).length
      }
    });
  }

  if (input.kind === 'snapshot') {
    if (!Array.isArray(input.files)) {
      throw Object.assign(new Error('input.files must be an array for kind=snapshot'), { statusCode: 400, code: 'INVALID_INPUT' });
    }
    const { maxFiles, maxFileBytes } = resolvedBounds(input, {
      defaultMaxFiles: 300,
      hardMaxFiles: 300,
      defaultMaxFileBytes: 200000,
      hardMaxFileBytes: 200000
    });
    const rawReport = analyzeFiles(
      {
        repository: input.repository || 'local/snapshot',
        files: input.files
      },
      {
        maxFiles,
        maxFileBytes
      }
    );
    return normalizeRunResult({
      rawReport,
      analysisWarnings: deriveSnapshotWarnings(input.files, maxFiles, maxFileBytes),
      sourceMeta: {
        totalFiles: input.files.length,
        analyzedFiles: rawReport.files.length
      }
    });
  }

  if (input.kind === 'github') {
    const owner = input.owner;
    const repo = input.repo;
    if (!owner || !repo) {
      throw Object.assign(new Error('input.owner and input.repo are required for kind=github'), { statusCode: 400, code: 'INVALID_INPUT' });
    }
    const { maxFiles, maxFileBytes } = resolvedBounds(input, {
      defaultMaxFiles: ANALYZE_GITHUB_DEFAULT_MAX_FILES,
      hardMaxFiles: ANALYZE_GITHUB_HARD_MAX_FILES,
      defaultMaxFileBytes: ANALYZE_GITHUB_DEFAULT_MAX_FILE_BYTES,
      hardMaxFileBytes: ANALYZE_GITHUB_HARD_MAX_FILE_BYTES
    });
    const repoSnapshot = await fetchRepoFiles(owner, repo, {
      token: input.token || '',
      maxFiles,
      maxFileBytes
    });
    const rawReport = analyzeFiles(repoSnapshot, { maxFiles, maxFileBytes });
    const warnings = [];
    const sourceMeta = repoSnapshot.sourceMeta || {};
    if (sourceMeta.skippedByMaxFiles > 0) {
      warnings.push({
        code: 'MAX_FILES_EXCEEDED',
        message: `${sourceMeta.skippedByMaxFiles} files skipped due to maxFiles bound.`,
        details: sourceMeta
      });
    }
    if (sourceMeta.truncatedByBytes > 0) {
      warnings.push({
        code: 'MAX_FILE_BYTES_TRUNCATION',
        message: `${sourceMeta.truncatedByBytes} files truncated due to maxFileBytes bound.`,
        details: sourceMeta
      });
    }
    return normalizeRunResult({
      rawReport,
      analysisWarnings: warnings,
      sourceMeta: Object.assign({}, sourceMeta, {
        totalFiles: sourceMeta.candidateFiles || rawReport.summary.totalFiles,
        analyzedFiles: rawReport.files.length
      })
    });
  }

  throw Object.assign(new Error('input.kind must be one of: codeflow-report, snapshot, github'), { statusCode: 400, code: 'INVALID_INPUT' });
}

async function processJob(jobId){
  const job = jobStore.get(jobId);
  if (!job) return;
  jobStore.update(jobId, { status: 'running' });
  try {
    const runResult = await runAnalysis(job.input.input);
    const normalizedReport = ReportCore.normalizeReport(runResult.rawReport);
    const workflow = ReportCore.buildWorkflow(normalizedReport);
    const compact = ReportCore.compactAgentView(normalizedReport);
    const actionable = ReportCore.actionableIssues(normalizedReport);
    jobStore.update(jobId, {
      status: 'completed',
      result: {
        schemaVersion: ReportCore.SCHEMA_VERSION,
        rawReport: runResult.rawReport,
        normalizedReport,
        compactAgentReport: compact,
        actionableIssues: actionable,
        workflow,
        analysisWarnings: runResult.analysisWarnings,
        sourceMeta: runResult.sourceMeta,
        cacheKey: AgentContract.hash(`${normalizedReport.reportId}:${ReportCore.SCHEMA_VERSION}`)
      }
    });
  } catch (err) {
    jobStore.update(jobId, {
      status: 'failed',
      error: {
        code: err.code || 'ANALYSIS_FAILED',
        message: err.message,
        statusCode: err.statusCode || 500
      }
    });
  }
}

function jobResponse(job){
  const response = {
    jobId: job.id,
    status: job.status,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    error: job.error
  };
  const token = signedJobToken(job.id);
  if (token) response.pollingToken = token;
  return response;
}

function v2Error(res, statusCode, requestId, code, message, details, job){
  sendV2(res, statusCode, {
    requestId,
    jobId: job && job.id,
    cacheKey: job && job.result && job.result.cacheKey,
    analysisWarnings: job && job.result && job.result.analysisWarnings ? job.result.analysisWarnings : [],
    errors: [{ code, message, details: details || undefined }]
  });
}

function getCompletedJob(jobId){
  const job = jobStore.get(jobId);
  if (!job) return { error: { statusCode: 404, code: 'JOB_NOT_FOUND', message: 'Job not found' } };
  if (job.status === 'failed') return { error: { statusCode: 422, code: 'ANALYSIS_FAILED', message: job.error && job.error.message ? job.error.message : 'Analysis failed' }, job };
  if (job.status !== 'completed') return { error: { statusCode: 409, code: 'INCOMPLETE_ANALYSIS', message: 'Job is not completed' }, job };
  return { job };
}

function createServer(){
  return http.createServer(async (req, res) => {
    const requestId = requestIdFrom(req);
    if (!enforceRateLimit(req, res, requestId)) return;

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const isV2 = url.pathname.startsWith('/api/v2/');
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        sendJson(res, 200, { ok: true, service: 'codeflow-agent-api', schemaVersion: ReportCore.SCHEMA_VERSION });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/v2/capabilities') {
        if (!hasScope(req, 'read')) {
          v2Error(res, 403, requestId, 'FORBIDDEN', 'Read scope required');
          return;
        }
        sendV2(res, 200, { requestId, data: AgentContract.buildCapabilities() });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/v2/schema') {
        if (!hasScope(req, 'read')) {
          v2Error(res, 403, requestId, 'FORBIDDEN', 'Read scope required');
          return;
        }
        sendV2(res, 200, { requestId, data: AgentContract.buildSchema() });
        return;
      }

      if (req.method === 'POST' && url.pathname === '/api/v1/analyze') {
        const body = await parseBody(req);
        const asyncMode = body.async !== false;
        const job = jobStore.create(body, { idempotencyKey: idempotencyKeyFromRequest(req, body) });
        if (asyncMode) {
          if (job.status === 'queued') setImmediate(() => { processJob(job.id); });
          sendJson(res, 202, jobResponse(job));
          return;
        }
        if (job.status !== 'completed' && job.status !== 'failed') await processJob(job.id);
        const processed = jobStore.get(job.id);
        if (processed.status === 'failed') {
          sendJson(res, processed.error.statusCode || 500, { error: processed.error.message, code: processed.error.code, jobId: processed.id });
          return;
        }
        sendJson(res, 200, {
          ...jobResponse(processed),
          result: processed.result,
          requestId
        });
        return;
      }

      if (req.method === 'GET' && /^\/api\/v1\/jobs\/[^/]+$/.test(url.pathname)) {
        const jobId = jobIdFromPath(url.pathname);
        const job = jobStore.get(jobId);
        if (!job) {
          sendJson(res, 404, { error: 'Job not found' });
          return;
        }
        sendJson(res, 200, {
          ...jobResponse(job),
          result: job.status === 'completed' ? job.result : undefined
        });
        return;
      }

      if (req.method === 'GET' && /^\/api\/v1\/jobs\/[^/]+\/report$/.test(url.pathname)) {
        const jobId = jobIdFromPath(url.pathname);
        const job = jobStore.get(jobId);
        if (!job) {
          sendJson(res, 404, { error: 'Job not found' });
          return;
        }
        if (job.status !== 'completed') {
          sendJson(res, 409, { error: 'Job is not completed', status: job.status });
          return;
        }
        sendJson(res, 200, job.result.normalizedReport);
        return;
      }

      if (req.method === 'GET' && /^\/api\/v1\/jobs\/[^/]+\/issues$/.test(url.pathname)) {
        const jobId = jobIdFromPath(url.pathname);
        const job = jobStore.get(jobId);
        if (!job) {
          sendJson(res, 404, { error: 'Job not found' });
          return;
        }
        if (job.status !== 'completed') {
          sendJson(res, 409, { error: 'Job is not completed', status: job.status });
          return;
        }
        sendJson(res, 200, {
          schemaVersion: ReportCore.SCHEMA_VERSION,
          reportId: job.result.normalizedReport.reportId,
          issues: job.result.actionableIssues
        });
        return;
      }

      if (req.method === 'GET' && /^\/api\/v1\/jobs\/[^/]+\/workflow$/.test(url.pathname)) {
        const jobId = jobIdFromPath(url.pathname);
        const job = jobStore.get(jobId);
        if (!job) {
          sendJson(res, 404, { error: 'Job not found' });
          return;
        }
        if (job.status !== 'completed') {
          sendJson(res, 409, { error: 'Job is not completed', status: job.status });
          return;
        }
        sendJson(res, 200, job.result.workflow);
        return;
      }

      if (req.method === 'GET' && /^\/api\/v1\/jobs\/[^/]+\/compact$/.test(url.pathname)) {
        const jobId = jobIdFromPath(url.pathname);
        const job = jobStore.get(jobId);
        if (!job) {
          sendJson(res, 404, { error: 'Job not found' });
          return;
        }
        if (job.status !== 'completed') {
          sendJson(res, 409, { error: 'Job is not completed', status: job.status });
          return;
        }
        sendJson(res, 200, job.result.compactAgentReport);
        return;
      }

      if (req.method === 'GET' && /^\/api\/v2\/agent\/[^/]+\/(overview|map|hotspots|dependencies|sanity|quality-gates|coverage|plan|checklists|change-impact)$/.test(url.pathname)) {
        if (!hasScope(req, 'read')) {
          v2Error(res, 403, requestId, 'FORBIDDEN', 'Read scope required');
          return;
        }
        const jobId = jobIdFromPath(url.pathname);
        if (!validateJobAccessToken(jobId, req, url)) {
          v2Error(res, 403, requestId, 'INVALID_JOB_TOKEN', 'A valid signed job access token is required for polling');
          return;
        }
        const lookup = getCompletedJob(jobId);
        if (lookup.error) {
          v2Error(res, lookup.error.statusCode, requestId, lookup.error.code, lookup.error.message, { status: lookup.job && lookup.job.status }, lookup.job);
          return;
        }
        const job = lookup.job;
        const endpoint = url.pathname.split('/').pop();
        if (endpoint === 'overview') {
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: AgentContract.buildOverview(job)
          });
          return;
        }
        if (endpoint === 'map') {
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: AgentContract.buildMap(job)
          });
          return;
        }
        if (endpoint === 'hotspots') {
          const pagination = AgentContract.parsePagination(url.searchParams);
          const paged = AgentContract.applyPagination(AgentContract.buildHotspots(job), pagination);
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            pageInfo: paged.pageInfo,
            analysisWarnings: job.result.analysisWarnings,
            data: { hotspots: paged.items }
          });
          return;
        }
        if (endpoint === 'dependencies') {
          const data = AgentContract.buildDependencies(job, url.searchParams);
          const pagination = AgentContract.parsePagination(url.searchParams);
          const paged = AgentContract.applyPagination(data.dependencies, pagination);
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            pageInfo: paged.pageInfo,
            analysisWarnings: job.result.analysisWarnings,
            data: Object.assign({}, data, { dependencies: paged.items })
          });
          return;
        }
        if (endpoint === 'sanity') {
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: AgentContract.buildSanity(job)
          });
          return;
        }
        if (endpoint === 'quality-gates') {
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: AgentContract.buildQualityGates(job, url.searchParams)
          });
          return;
        }
        if (endpoint === 'coverage') {
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: AgentContract.buildCoverage(job)
          });
          return;
        }
        if (endpoint === 'plan') {
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: AgentContract.buildPlan(job)
          });
          return;
        }
        if (endpoint === 'checklists') {
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: { checklists: AgentContract.buildChecklists(job) }
          });
          return;
        }
        if (endpoint === 'change-impact') {
          const filesArg = url.searchParams.get('files');
          if (!filesArg) {
            v2Error(res, 400, requestId, 'INVALID_INPUT', 'Query parameter "files" is required');
            return;
          }
          sendV2(res, 200, {
            requestId,
            jobId,
            cacheKey: job.result.cacheKey,
            analysisWarnings: job.result.analysisWarnings,
            data: AgentContract.buildChangeImpact(job, url.searchParams)
          });
          return;
        }
      }

      if (req.method === 'GET' && url.pathname === '/api/v2/admin/config') {
        if (!hasScope(req, 'admin')) {
          v2Error(res, 403, requestId, 'FORBIDDEN', 'Admin scope required');
          return;
        }
        sendV2(res, 200, {
          requestId,
          data: {
            rateLimit: {
              windowMs: RATE_LIMIT_WINDOW_MS,
              maxRequests: RATE_LIMIT_MAX
            },
            requestBodyMaxBytes: MAX_REQUEST_BODY_SIZE
          }
        });
        return;
      }

      if (isV2) {
        v2Error(res, 404, requestId, 'NOT_FOUND', 'Not found');
        return;
      }

      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      if (isV2) {
        v2Error(res, err.statusCode || 500, requestId, err.code || 'INTERNAL_ERROR', err.message || 'Internal server error');
        return;
      }
      sendJson(res, err.statusCode || 500, {
        error: err.message || 'Internal server error'
      });
    }
  });
}

if (require.main === module) {
  const server = createServer();
  server.listen(DEFAULT_PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`CodeFlow Agent API listening on http://localhost:${DEFAULT_PORT}`);
  });
}

module.exports = {
  createServer,
  runAnalysis
};
function resolvedBounds(input, defaults){
  return {
    maxFiles: Math.min(input.maxFiles || defaults.defaultMaxFiles, defaults.hardMaxFiles),
    maxFileBytes: Math.min(input.maxFileBytes || defaults.defaultMaxFileBytes, defaults.hardMaxFileBytes)
  };
}
