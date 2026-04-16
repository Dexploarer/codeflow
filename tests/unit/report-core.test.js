const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const ReportCore = require('../../shared/report-core');

function fixture(name){
  const p = path.join(__dirname, '../fixtures', name);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

test('normalizeReport outputs deterministic IDs and structured findings', () => {
  const raw = fixture('sample-report.json');
  const normalizedA = ReportCore.normalizeReport(raw);
  const normalizedB = ReportCore.normalizeReport(raw);

  assert.equal(normalizedA.schemaVersion, '1.0.0');
  assert.equal(normalizedA.reportId, normalizedB.reportId);
  assert.ok(normalizedA.findings.security.length > 0);
  assert.ok(normalizedA.findings.architecture.length > 0);
  assert.ok(normalizedA.findings.deadCode.length > 0);
  assert.ok(normalizedA.findings.duplicates.length > 0);
  assert.ok(normalizedA.findings.layerViolations.length > 0);
});

test('buildWorkflow creates ordered tasks with metadata', () => {
  const raw = fixture('sample-report.json');
  const normalized = ReportCore.normalizeReport(raw);
  const workflow = ReportCore.buildWorkflow(normalized);

  assert.equal(workflow.schemaVersion, '1.0.0');
  assert.ok(Array.isArray(workflow.tasks));
  assert.ok(workflow.tasks.length > 0);
  assert.ok(workflow.tasks[0].title.startsWith('Remediate:'));
  assert.ok(Array.isArray(workflow.tasks[0].acceptanceCriteria));
});

test('compactAgentView returns machine-friendly reduced payload', () => {
  const raw = fixture('sample-report.json');
  const normalized = ReportCore.normalizeReport(raw);
  const compact = ReportCore.compactAgentView(normalized);

  assert.equal(compact.schemaVersion, '1.0.0');
  assert.equal(compact.repository, raw.repository);
  assert.ok(compact.summary.totalFindings >= 1);
  assert.ok(Array.isArray(compact.topFindings));
});
