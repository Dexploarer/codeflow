const crypto = require('crypto');
const ReportCore = require('../shared/report-core');

const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 200;

const DEFAULT_QUALITY_GATES = {
  highSeverityMax: 0,
  layerViolationMax: 5
};

function hash(input){
  return crypto.createHash('sha256').update(String(input || '')).digest('hex').slice(0, 16);
}

function safeArray(value){
  return Array.isArray(value) ? value : [];
}

function asNumber(value, fallback){
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function ext(path){
  const value = String(path || '');
  const index = value.lastIndexOf('.');
  return index === -1 ? 'unknown' : value.slice(index + 1).toLowerCase();
}

function folderOf(path){
  const value = String(path || '');
  const idx = value.lastIndexOf('/');
  return idx === -1 ? 'root' : value.slice(0, idx);
}

function parsePagination(query){
  const page = Math.max(1, Math.floor(asNumber(query.get('page'), 1)));
  const pageSize = Math.max(1, Math.min(MAX_PAGE_SIZE, Math.floor(asNumber(query.get('pageSize'), DEFAULT_PAGE_SIZE))));
  return { page, pageSize };
}

function applyPagination(list, pagination){
  const totalItems = list.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pagination.pageSize));
  const page = Math.min(pagination.page, totalPages);
  const start = (page - 1) * pagination.pageSize;
  const end = start + pagination.pageSize;
  return {
    items: list.slice(start, end),
    pageInfo: {
      page,
      pageSize: pagination.pageSize,
      totalItems,
      totalPages
    }
  };
}

function findingCounts(normalized){
  const findings = normalized && normalized.findings ? normalized.findings : {};
  return {
    security: safeArray(findings.security).length,
    architecture: safeArray(findings.architecture).length + safeArray(findings.layerViolations).length,
    maintainability: safeArray(findings.deadCode).length + safeArray(findings.duplicates).length,
    total: safeArray(findings.all).length
  };
}

function buildOverview(job){
  const normalized = job.result.normalizedReport;
  const raw = normalized.rawReport || {};
  const counts = findingCounts(normalized);
  const byFile = new Map();
  safeArray(normalized.findings.all).forEach((finding) => {
    safeArray(finding.targetFiles).forEach((file) => {
      byFile.set(file, (byFile.get(file) || 0) + 1);
    });
  });
  const fileHotspots = safeArray(raw.files)
    .map((file) => ({
      path: file.path,
      layer: file.layer || 'modules',
      lines: file.lines || 0,
      functionCount: file.functionCount || safeArray(file.functions).length,
      findingCount: byFile.get(file.path) || 0,
      complexity: (file.functionCount || 0) * 2 + (file.lines || 0) / 50 + (byFile.get(file.path) || 0) * 3
    }))
    .sort((a, b) => b.complexity - a.complexity || b.findingCount - a.findingCount || a.path.localeCompare(b.path))
    .slice(0, 10);

  const riskScore = Math.min(100, counts.security * 20 + counts.architecture * 10 + counts.maintainability * 5);
  const risk = riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : 'low';

  return {
    repository: normalized.repository,
    reportId: normalized.reportId,
    summary: {
      healthScore: normalized.summary.healthScore,
      healthGrade: normalized.summary.healthGrade,
      totalFindings: counts.total,
      findingsByCategory: counts
    },
    risk: { level: risk, score: riskScore },
    architecture: {
      totalFolders: safeArray(raw.folderStructure).length,
      totalDependencies: safeArray(raw.dependencies).length,
      layerViolations: safeArray(raw.layerViolations).length
    },
    languageMix: safeArray(raw.languageBreakdown),
    topHotspots: fileHotspots
  };
}

function buildMap(job){
  const raw = job.result.normalizedReport.rawReport || {};
  const files = safeArray(raw.files);
  const edges = new Map();
  const folders = new Map();

  files.forEach((file) => {
    const folder = file.folder || folderOf(file.path);
    const existing = folders.get(folder) || { folder, files: 0, functions: 0, layers: new Set() };
    existing.files += 1;
    existing.functions += file.functionCount || safeArray(file.functions).length;
    if (file.layer) existing.layers.add(file.layer);
    folders.set(folder, existing);
  });

  safeArray(raw.dependencies).forEach((dep) => {
    const fromFolder = folderOf(dep.from);
    const toFolder = folderOf(dep.to);
    const key = `${fromFolder}->${toFolder}`;
    const edge = edges.get(key) || { from: fromFolder, to: toFolder, calls: 0, dependencies: 0 };
    edge.calls += dep.callCount || 1;
    edge.dependencies += 1;
    edges.set(key, edge);
  });

  return {
    reportId: job.result.normalizedReport.reportId,
    nodes: Array.from(folders.values())
      .map((folder) => ({
        folder: folder.folder,
        files: folder.files,
        functions: folder.functions,
        layers: Array.from(folder.layers).sort()
      }))
      .sort((a, b) => b.files - a.files || a.folder.localeCompare(b.folder)),
    edges: Array.from(edges.values()).sort((a, b) => b.calls - a.calls || a.from.localeCompare(b.from))
  };
}

function buildHotspots(job){
  const raw = job.result.normalizedReport.rawReport || {};
  const files = safeArray(raw.files);
  const findingWeight = new Map();
  safeArray(job.result.normalizedReport.findings.all).forEach((finding) => {
    const weight = finding.severity === 'critical' ? 5 : finding.severity === 'high' ? 4 : finding.severity === 'medium' ? 3 : 2;
    safeArray(finding.targetFiles).forEach((target) => {
      findingWeight.set(target, (findingWeight.get(target) || 0) + weight);
    });
  });

  return files
    .map((file) => {
      const complexity = (file.lines || 0) / 40 + (file.functionCount || 0) * 2;
      const blastRadius = safeArray(raw.dependencies).filter((dep) => dep.from === file.path || dep.to === file.path).length;
      const churn = file.churn || 0;
      const riskScore = Math.round(complexity + blastRadius * 1.5 + churn + (findingWeight.get(file.path) || 0));
      return {
        path: file.path,
        layer: file.layer || 'modules',
        complexity: Number(complexity.toFixed(2)),
        churn,
        blastRadius,
        findingWeight: findingWeight.get(file.path) || 0,
        riskScore
      };
    })
    .sort((a, b) => b.riskScore - a.riskScore || a.path.localeCompare(b.path));
}

function buildDependencies(job, query){
  const raw = job.result.normalizedReport.rawReport || {};
  const allDeps = safeArray(raw.dependencies).map((dep) => ({
    from: dep.from,
    to: dep.to,
    function: dep.function || '',
    callCount: dep.callCount || 1
  }));
  const files = safeArray(raw.files);
  const layerByFile = new Map(files.map((file) => [file.path, file.layer || 'modules']));
  const fileFilter = query.get('file');
  const layerFilter = query.get('layer');
  const direction = query.get('direction') || 'both';
  const depth = Math.max(1, Math.min(5, Math.floor(asNumber(query.get('depth'), 1))));

  let deps = allDeps.slice();
  if (fileFilter) {
    if (direction === 'inbound') deps = deps.filter((dep) => dep.to === fileFilter);
    else if (direction === 'outbound') deps = deps.filter((dep) => dep.from === fileFilter);
    else deps = deps.filter((dep) => dep.from === fileFilter || dep.to === fileFilter);
  }
  if (layerFilter) {
    deps = deps.filter((dep) => layerByFile.get(dep.from) === layerFilter || layerByFile.get(dep.to) === layerFilter);
  }

  if (fileFilter && depth > 1) {
    const visited = new Set([fileFilter]);
    let frontier = new Set([fileFilter]);
    for (let i = 0; i < depth; i += 1) {
      const next = new Set();
      allDeps.forEach((dep) => {
        if (frontier.has(dep.from) && !visited.has(dep.to)) next.add(dep.to);
        if (direction !== 'outbound' && frontier.has(dep.to) && !visited.has(dep.from)) next.add(dep.from);
      });
      next.forEach((node) => visited.add(node));
      frontier = next;
      if (!frontier.size) break;
    }
    deps = deps.filter((dep) => visited.has(dep.from) || visited.has(dep.to));
  }

  const ranked = deps.sort((a, b) => b.callCount - a.callCount || a.from.localeCompare(b.from));
  return {
    filters: { file: fileFilter || null, layer: layerFilter || null, direction, depth },
    total: ranked.length,
    dependencies: ranked
  };
}

function buildSanity(job){
  const normalized = job.result.normalizedReport;
  const raw = normalized.rawReport || {};
  const checks = [];
  const schemaValid = normalized.schemaVersion === ReportCore.SCHEMA_VERSION;
  checks.push({ id: 'schema-version', passed: schemaValid, detail: schemaValid ? 'Schema matches current contract.' : 'Schema mismatch.' });

  const hasFindings = Array.isArray(normalized.findings && normalized.findings.all);
  checks.push({ id: 'findings-array', passed: hasFindings, detail: hasFindings ? 'Findings available.' : 'Missing findings array.' });

  const fileCount = safeArray(raw.files).length;
  const summaryFiles = asNumber(raw.summary && raw.summary.totalFiles, fileCount);
  const complete = fileCount > 0 && summaryFiles >= fileCount;
  checks.push({ id: 'analysis-completeness', passed: complete, detail: complete ? 'Analyzed file coverage available.' : 'Missing or inconsistent analyzed file coverage.' });

  const suspiciousParserGaps = [];
  if (summaryFiles > fileCount) {
    suspiciousParserGaps.push({
      kind: 'missing-files',
      expected: summaryFiles,
      analyzed: fileCount
    });
  }
  const nonCode = safeArray(raw.files).filter((file) => file.isCode === false).length;
  if (nonCode > 0) {
    suspiciousParserGaps.push({
      kind: 'non-code-files',
      count: nonCode
    });
  }
  const warningPenalty = safeArray(job.result.analysisWarnings).length * 8;
  const passedCount = checks.filter((check) => check.passed).length;
  const confidenceScore = Math.max(0, Math.min(100, Math.round((passedCount / checks.length) * 100) - warningPenalty - suspiciousParserGaps.length * 5));

  return {
    status: checks.every((check) => check.passed) ? 'pass' : 'fail',
    confidenceScore,
    checks,
    parserGaps: suspiciousParserGaps
  };
}

function buildQualityGates(job, query){
  const highSeverityMax = Math.max(0, Math.floor(asNumber(query.get('highSeverityMax'), DEFAULT_QUALITY_GATES.highSeverityMax)));
  const layerViolationMax = Math.max(0, Math.floor(asNumber(query.get('layerViolationMax'), DEFAULT_QUALITY_GATES.layerViolationMax)));
  const normalized = job.result.normalizedReport;
  const highSeverity = safeArray(normalized.findings.all).filter((finding) => finding.severity === 'high' || finding.severity === 'critical').length;
  const layerViolations = safeArray(normalized.findings.layerViolations).length;
  const gates = [
    {
      id: 'high-severity-findings',
      actual: highSeverity,
      threshold: highSeverityMax,
      passed: highSeverity <= highSeverityMax
    },
    {
      id: 'layer-violations',
      actual: layerViolations,
      threshold: layerViolationMax,
      passed: layerViolations <= layerViolationMax
    }
  ];
  return {
    status: gates.every((gate) => gate.passed) ? 'pass' : 'fail',
    gates
  };
}

function buildCoverage(job){
  const raw = job.result.normalizedReport.rawReport || {};
  const files = safeArray(raw.files);
  const analyzed = files.length;
  const code = files.filter((file) => file.isCode !== false).length;
  const nonCode = analyzed - code;
  const summaryTotal = asNumber(raw.summary && raw.summary.totalFiles, analyzed);
  const skipped = Math.max(0, summaryTotal - analyzed);
  const byExtension = {};
  files.forEach((file) => {
    const fileExt = ext(file.path);
    byExtension[fileExt] = (byExtension[fileExt] || 0) + 1;
  });
  const warnings = safeArray(job.result.analysisWarnings);
  return {
    analyzed,
    codeFiles: code,
    nonCodeFiles: nonCode,
    skipped,
    truncation: {
      hasTruncation: warnings.some((warning) => warning.code === 'MAX_FILE_BYTES_TRUNCATION' || warning.code === 'PAYLOAD_TRUNCATED'),
      warnings
    },
    extensions: Object.entries(byExtension).map(([fileExt, count]) => ({ extension: fileExt, count })).sort((a, b) => b.count - a.count || a.extension.localeCompare(b.extension))
  };
}

function buildPlan(job){
  const workflow = job.result.workflow;
  const tasks = safeArray(workflow.tasks);
  const bundles = new Map();
  tasks.forEach((task) => {
    const subsystem = folderOf((task.targetFiles && task.targetFiles[0]) || 'root');
    const entry = bundles.get(subsystem) || { subsystem, taskCount: 0, tasks: [] };
    entry.taskCount += 1;
    entry.tasks.push({
      id: task.id,
      findingId: task.findingId,
      title: task.title,
      order: task.order,
      priority: task.priority,
      severity: task.severity,
      dependsOn: task.dependsOn
    });
    bundles.set(subsystem, entry);
  });
  const orderedBundles = Array.from(bundles.values())
    .map((bundle) => ({ ...bundle, tasks: bundle.tasks.sort((a, b) => a.order - b.order || a.id.localeCompare(b.id)) }))
    .sort((a, b) => b.taskCount - a.taskCount || a.subsystem.localeCompare(b.subsystem));
  return {
    strategy: workflow.strategy || ['security', 'architecture', 'maintainability'],
    bundles: orderedBundles
  };
}

function buildChecklists(job){
  const tasks = safeArray(job.result.workflow && job.result.workflow.tasks);
  const byCategory = new Map();
  tasks.forEach((task) => {
    const list = byCategory.get(task.category) || { category: task.category, checks: new Set(), taskIds: [] };
    safeArray(task.acceptanceCriteria).forEach((item) => list.checks.add(item));
    list.taskIds.push(task.id);
    byCategory.set(task.category, list);
  });
  return Array.from(byCategory.values())
    .map((entry) => ({
      category: entry.category,
      taskIds: entry.taskIds.sort(),
      checks: Array.from(entry.checks).sort(),
      regressionChecks: [
        `Re-run analysis and ensure no increase in ${entry.category || 'general'} findings.`,
        'Run affected test suites and smoke tests.'
      ]
    }))
    .sort((a, b) => a.category.localeCompare(b.category));
}

function buildChangeImpact(job, query){
  const raw = job.result.normalizedReport.rawReport || {};
  const files = String(query.get('files') || '')
    .split(',')
    .map((file) => file.trim())
    .filter(Boolean);
  const deps = safeArray(raw.dependencies);
  const impacted = new Set(files);
  const queue = [...files];
  while (queue.length) {
    const file = queue.shift();
    deps.forEach((dep) => {
      if (dep.from === file && !impacted.has(dep.to)) {
        impacted.add(dep.to);
        queue.push(dep.to);
      }
      if (dep.to === file && !impacted.has(dep.from)) {
        impacted.add(dep.from);
        queue.push(dep.from);
      }
    });
  }
  const affectedFindings = safeArray(job.result.normalizedReport.findings.all).filter((finding) => safeArray(finding.targetFiles).some((file) => impacted.has(file)));
  return {
    requestedFiles: files,
    impactedFiles: Array.from(impacted).sort(),
    impactedFindings: affectedFindings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title
    })),
    testImpact: {
      suggestedScope: impacted.size > 20 ? 'full' : impacted.size > 5 ? 'integration-and-unit' : 'targeted-unit',
      reason: `Detected ${impacted.size} impacted files from dependency traversal.`
    }
  };
}

function buildCapabilities(){
  return {
    version: '2.0.0',
    schemaVersion: ReportCore.SCHEMA_VERSION,
    endpoints: [
      '/api/v2/capabilities',
      '/api/v2/schema',
      '/api/v2/agent/:jobId/overview',
      '/api/v2/agent/:jobId/map',
      '/api/v2/agent/:jobId/hotspots',
      '/api/v2/agent/:jobId/dependencies',
      '/api/v2/agent/:jobId/sanity',
      '/api/v2/agent/:jobId/quality-gates',
      '/api/v2/agent/:jobId/coverage',
      '/api/v2/agent/:jobId/plan',
      '/api/v2/agent/:jobId/checklists',
      '/api/v2/agent/:jobId/change-impact'
    ],
    auth: {
      readScopeRequired: Boolean(process.env.CODEFLOW_API_READ_TOKEN),
      adminScopeRequired: Boolean(process.env.CODEFLOW_API_ADMIN_TOKEN)
    },
    pagination: {
      supported: true,
      defaultPageSize: DEFAULT_PAGE_SIZE,
      maxPageSize: MAX_PAGE_SIZE
    }
  };
}

function buildSchema(){
  return {
    version: '2.0.0',
    envelope: {
      meta: {
        requestId: 'string',
        schemaVersion: 'string',
        jobId: 'string|null',
        cacheKey: 'string|null',
        pageInfo: 'object|null',
        analysisWarnings: 'array'
      },
      data: 'any',
      errors: [{ code: 'string', message: 'string', details: 'object?' }]
    }
  };
}

module.exports = {
  parsePagination,
  applyPagination,
  hash,
  buildOverview,
  buildMap,
  buildHotspots,
  buildDependencies,
  buildSanity,
  buildQualityGates,
  buildCoverage,
  buildPlan,
  buildChecklists,
  buildChangeImpact,
  buildCapabilities,
  buildSchema
};
