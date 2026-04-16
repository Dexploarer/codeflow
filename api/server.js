const http = require('http');
const { URL } = require('url');
const { analyzeFiles } = require('./analyzer');
const { fetchRepoFiles } = require('./github-client');
const { JobStore } = require('./job-store');
const ReportCore = require('../shared/report-core');

const DEFAULT_PORT = Number(process.env.PORT || 8787);
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 60;
const jobStore = new JobStore();
const requestBuckets = new Map();

function sendJson(res, statusCode, data){
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function parseBody(req){
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 5 * 1024 * 1024) {
        reject(Object.assign(new Error('Payload too large'), { statusCode: 413 }));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(Object.assign(new Error('Invalid JSON body'), { statusCode: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function clientKey(req){
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function enforceRateLimit(req, res){
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
    sendJson(res, 429, {
      error: 'Rate limit exceeded',
      detail: `Allowed ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW_MS / 1000}s window.`
    });
    return false;
  }
  return true;
}

async function runAnalysis(input){
  if (!input || typeof input !== 'object') {
    const err = new Error('input object is required');
    err.statusCode = 400;
    throw err;
  }

  if (input.kind === 'codeflow-report') {
    if (!input.report || typeof input.report !== 'object') {
      const err = new Error('input.report is required for kind=codeflow-report');
      err.statusCode = 400;
      throw err;
    }
    return input.report;
  }

  if (input.kind === 'snapshot') {
    if (!Array.isArray(input.files)) {
      const err = new Error('input.files must be an array for kind=snapshot');
      err.statusCode = 400;
      throw err;
    }
    return analyzeFiles(
      {
        repository: input.repository || 'local/snapshot',
        files: input.files
      },
      {
        maxFiles: input.maxFiles || 300,
        maxFileBytes: input.maxFileBytes || 200000
      }
    );
  }

  if (input.kind === 'github') {
    const owner = input.owner;
    const repo = input.repo;
    if (!owner || !repo) {
      const err = new Error('input.owner and input.repo are required for kind=github');
      err.statusCode = 400;
      throw err;
    }
    const repoSnapshot = await fetchRepoFiles(owner, repo, {
      token: input.token || '',
      maxFiles: Math.min(input.maxFiles || 200, 300),
      maxFileBytes: Math.min(input.maxFileBytes || 120000, 200000)
    });
    return analyzeFiles(repoSnapshot, {
      maxFiles: Math.min(input.maxFiles || 200, 300),
      maxFileBytes: Math.min(input.maxFileBytes || 120000, 200000)
    });
  }

  const err = new Error('input.kind must be one of: codeflow-report, snapshot, github');
  err.statusCode = 400;
  throw err;
}

async function processJob(jobId){
  const job = jobStore.get(jobId);
  if (!job) return;
  jobStore.update(jobId, { status: 'running' });
  try {
    const rawReport = await runAnalysis(job.input.input);
    const normalizedReport = ReportCore.normalizeReport(rawReport);
    const workflow = ReportCore.buildWorkflow(normalizedReport);
    const compact = ReportCore.compactAgentView(normalizedReport);
    const actionable = ReportCore.actionableIssues(normalizedReport);
    jobStore.update(jobId, {
      status: 'completed',
      result: {
        schemaVersion: ReportCore.SCHEMA_VERSION,
        rawReport,
        normalizedReport,
        compactAgentReport: compact,
        actionableIssues: actionable,
        workflow
      }
    });
  } catch (err) {
    jobStore.update(jobId, {
      status: 'failed',
      error: {
        message: err.message,
        statusCode: err.statusCode || 500
      }
    });
  }
}

function jobResponse(job){
  return {
    jobId: job.id,
    status: job.status,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    error: job.error
  };
}

function createServer(){
  return http.createServer(async (req, res) => {
    if (!enforceRateLimit(req, res)) return;
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        sendJson(res, 200, { ok: true, service: 'codeflow-agent-api', schemaVersion: ReportCore.SCHEMA_VERSION });
        return;
      }

      if (req.method === 'POST' && url.pathname === '/api/v1/analyze') {
        const body = await parseBody(req);
        const asyncMode = body.async !== false;
        const job = jobStore.create(body);
        if (asyncMode) {
          setImmediate(() => { processJob(job.id); });
          sendJson(res, 202, jobResponse(job));
          return;
        }
        await processJob(job.id);
        const processed = jobStore.get(job.id);
        if (processed.status === 'failed') {
          sendJson(res, processed.error.statusCode || 500, { error: processed.error.message, jobId: processed.id });
          return;
        }
        sendJson(res, 200, {
          ...jobResponse(processed),
          result: processed.result
        });
        return;
      }

      if (req.method === 'GET' && /^\/api\/v1\/jobs\/[^/]+$/.test(url.pathname)) {
        const jobId = url.pathname.split('/').pop();
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
        const jobId = url.pathname.split('/')[4];
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
        const jobId = url.pathname.split('/')[4];
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
        const jobId = url.pathname.split('/')[4];
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
        const jobId = url.pathname.split('/')[4];
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

      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
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
