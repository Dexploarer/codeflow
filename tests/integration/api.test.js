const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { createServer } = require('/home/runner/work/codeflow/codeflow/api/server');

function fixture(name){
  const p = path.join('/home/runner/work/codeflow/codeflow/tests/fixtures', name);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function requestJson(baseUrl, method, route, payload){
  const url = new URL(route, baseUrl);
  const body = payload ? JSON.stringify(payload) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(url, {
      method,
      headers: Object.assign(
        { 'Content-Type': 'application/json' },
        body ? { 'Content-Length': Buffer.byteLength(body) } : {}
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
