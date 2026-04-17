const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { createServer } = require('../../api/server');

function fixture(name){
  const p = path.join(__dirname, '../fixtures', name);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function requestJson(baseUrl, method, route, payload, headers = {}){
  const url = new URL(route, baseUrl);
  const body = payload ? JSON.stringify(payload) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(url, {
      method,
      headers: Object.assign(
        { 'Content-Type': 'application/json' },
        body ? { 'Content-Length': Buffer.byteLength(body) } : {},
        headers
      )
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, body: data ? JSON.parse(data) : null });
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function seedJob(baseUrl){
  const raw = fixture('sample-report.json');
  const response = await requestJson(baseUrl, 'POST', '/api/v1/analyze', {
    async: false,
    idempotencyKey: 'seed-job',
    input: {
      kind: 'codeflow-report',
      report: raw
    }
  });
  assert.equal(response.statusCode, 200);
  return response.body.jobId;
}

test('analyze -> report -> workflow API flow', async (t) => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const raw = fixture('sample-report.json');

  const analyzeResponse = await requestJson(baseUrl, 'POST', '/api/v1/analyze', {
    async: false,
    input: {
      kind: 'codeflow-report',
      report: raw
    }
  });

  assert.equal(analyzeResponse.statusCode, 200);
  assert.equal(analyzeResponse.body.status, 'completed');
  assert.ok(analyzeResponse.body.result.normalizedReport.reportId);
  const jobId = analyzeResponse.body.jobId;

  const reportResponse = await requestJson(baseUrl, 'GET', `/api/v1/jobs/${jobId}/report`);
  assert.equal(reportResponse.statusCode, 200);
  assert.equal(reportResponse.body.repository, 'acme/demo');

  const issuesResponse = await requestJson(baseUrl, 'GET', `/api/v1/jobs/${jobId}/issues`);
  assert.equal(issuesResponse.statusCode, 200);
  assert.ok(Array.isArray(issuesResponse.body.issues));
  assert.ok(issuesResponse.body.issues.length > 0);

  const workflowResponse = await requestJson(baseUrl, 'GET', `/api/v1/jobs/${jobId}/workflow`);
  assert.equal(workflowResponse.statusCode, 200);
  assert.ok(Array.isArray(workflowResponse.body.tasks));
  assert.ok(workflowResponse.body.tasks.length > 0);
});

test('v1 idempotency keys return same job', async (t) => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const raw = fixture('sample-report.json');

  const first = await requestJson(baseUrl, 'POST', '/api/v1/analyze', {
    async: false,
    input: { kind: 'codeflow-report', report: raw }
  }, { 'Idempotency-Key': 'same-request' });
  const second = await requestJson(baseUrl, 'POST', '/api/v1/analyze', {
    async: false,
    input: { kind: 'codeflow-report', report: raw }
  }, { 'Idempotency-Key': 'same-request' });

  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(first.body.jobId, second.body.jobId);
});

test('v2 endpoints return envelope and golden outputs for overview/sanity/plan', async (t) => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const jobId = await seedJob(baseUrl);

  const overview = await requestJson(baseUrl, 'GET', `/api/v2/agent/${jobId}/overview`);
  const sanity = await requestJson(baseUrl, 'GET', `/api/v2/agent/${jobId}/sanity`);
  const plan = await requestJson(baseUrl, 'GET', `/api/v2/agent/${jobId}/plan`);

  assert.equal(overview.statusCode, 200);
  assert.equal(sanity.statusCode, 200);
  assert.equal(plan.statusCode, 200);
  assert.ok(overview.body.meta.requestId);
  assert.ok(overview.body.meta.cacheKey);
  assert.deepEqual(overview.body.errors, []);

  const expectedOverview = fixture('golden-overview.json');
  assert.equal(overview.body.data.repository, expectedOverview.repository);
  assert.deepEqual(overview.body.data.summary, expectedOverview.summary);
  assert.deepEqual(overview.body.data.risk, expectedOverview.risk);
  assert.deepEqual(overview.body.data.architecture, expectedOverview.architecture);
  assert.deepEqual(overview.body.data.languageMix, expectedOverview.languageMix);
  assert.equal(overview.body.data.topHotspots.length, expectedOverview.topHotspotsLength);

  const expectedSanity = fixture('golden-sanity.json');
  const sanityChecks = Object.fromEntries(sanity.body.data.checks.map((check) => [check.id, check.passed]));
  assert.equal(sanity.body.data.status, expectedSanity.status);
  assert.equal(sanity.body.data.confidenceScore, expectedSanity.confidenceScore);
  assert.deepEqual(sanityChecks, expectedSanity.checks);
  assert.deepEqual(sanity.body.data.parserGaps, expectedSanity.parserGaps);

  const expectedPlan = fixture('golden-plan.json');
  assert.deepEqual(plan.body.data.strategy, expectedPlan.strategy);
  const actualBundles = plan.body.data.bundles.map((bundle) => ({
    subsystem: bundle.subsystem,
    taskCount: bundle.taskCount,
    taskOrders: bundle.tasks.map((task) => task.order)
  }));
  assert.deepEqual(actualBundles, expectedPlan.bundles);
});

test('v2 discovery, pagination, filters, and structured errors', async (t) => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const jobId = await seedJob(baseUrl);

  const capabilities = await requestJson(baseUrl, 'GET', '/api/v2/capabilities');
  assert.equal(capabilities.statusCode, 200);
  assert.ok(Array.isArray(capabilities.body.data.endpoints));
  assert.ok(capabilities.body.data.endpoints.includes('/api/v2/agent/:jobId/overview'));

  const schema = await requestJson(baseUrl, 'GET', '/api/v2/schema');
  assert.equal(schema.statusCode, 200);
  assert.equal(schema.body.data.version, '2.0.0');

  const hotspots = await requestJson(baseUrl, 'GET', `/api/v2/agent/${jobId}/hotspots?page=1&pageSize=1`);
  assert.equal(hotspots.statusCode, 200);
  assert.equal(hotspots.body.meta.pageInfo.page, 1);
  assert.equal(hotspots.body.meta.pageInfo.pageSize, 1);

  const dependencies = await requestJson(baseUrl, 'GET', `/api/v2/agent/${jobId}/dependencies?file=src/service.js&direction=outbound`);
  assert.equal(dependencies.statusCode, 200);
  assert.equal(dependencies.body.data.filters.file, 'src/service.js');
  assert.equal(dependencies.body.data.filters.direction, 'outbound');

  const missingFiles = await requestJson(baseUrl, 'GET', `/api/v2/agent/${jobId}/change-impact`);
  assert.equal(missingFiles.statusCode, 400);
  assert.equal(missingFiles.body.errors[0].code, 'INVALID_INPUT');

  const missingJob = await requestJson(baseUrl, 'GET', '/api/v2/agent/nonexistent/overview');
  assert.equal(missingJob.statusCode, 404);
  assert.equal(missingJob.body.errors[0].code, 'JOB_NOT_FOUND');
});

test('API error responses for malformed input and missing jobs', async (t) => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const malformed = await requestJson(baseUrl, 'POST', '/api/v1/analyze', {
    async: false,
    input: { kind: 'snapshot' }
  });
  assert.equal(malformed.statusCode, 400);
  assert.match(malformed.body.error, /input\.files/i);

  const missingJob = await requestJson(baseUrl, 'GET', '/api/v1/jobs/nonexistent/report');
  assert.equal(missingJob.statusCode, 404);
  assert.equal(missingJob.body.error, 'Job not found');
});
