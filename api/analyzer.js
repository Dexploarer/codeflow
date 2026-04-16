const path = require('path');

const CODE_EXTENSIONS = new Set([
  '.js','.jsx','.ts','.tsx','.py','.java','.go','.rb','.php','.rs','.c','.h','.cpp','.hpp','.cs','.swift','.kt','.scala','.sh'
]);

function safeArray(value){ return Array.isArray(value) ? value : []; }
function extOf(filePath){ return path.extname(filePath || '').toLowerCase(); }
function basename(filePath){ return (filePath || '').split('/').pop() || filePath || ''; }
function folderOf(filePath){
  if(!filePath || !filePath.includes('/')) return 'root';
  return filePath.slice(0, filePath.lastIndexOf('/'));
}

function detectLayer(filePath){
  const p = (filePath || '').toLowerCase();
  if (p.includes('/test') || p.includes('.test.') || p.includes('.spec.')) return 'test';
  if (p.includes('/ui') || p.includes('/view') || p.includes('/component') || p.includes('/pages')) return 'ui';
  if (p.includes('/service') || p.includes('/api') || p.includes('/controller')) return 'services';
  if (p.includes('/data') || p.includes('/db') || p.includes('/store')) return 'data';
  if (p.includes('/config')) return 'config';
  if (p.includes('/util') || p.includes('/helper') || p.includes('/lib')) return 'utils';
  return 'modules';
}

function extractFunctions(content, filePath){
  const text = String(content || '');
  const ext = extOf(filePath);
  const found = [];
  const seen = new Set();
  const patterns = [];

  if (['.js','.jsx','.ts','.tsx'].includes(ext)) {
    patterns.push(/\b(?:export\s+)?function\s+([A-Za-z_]\w*)\s*\(/g);
    patterns.push(/\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s*)?(?:function|\(?.*?\)?\s*=>)/g);
    patterns.push(/\bclass\s+([A-Za-z_]\w*)/g);
  } else if (ext === '.py') {
    patterns.push(/^\s*def\s+([A-Za-z_]\w*)\s*\(/gm);
    patterns.push(/^\s*class\s+([A-Za-z_]\w*)\s*(?:\(|:)/gm);
  } else {
    patterns.push(/\b([A-Za-z_]\w*)\s*\([^)]*\)\s*\{/g);
  }

  patterns.forEach((pattern) => {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const name = match[1];
      const index = match.index;
      const line = text.slice(0, index).split('\n').length;
      const key = `${name}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ name, line, code: text.split('\n')[line - 1] || '' });
    }
  });

  return found.slice(0, 200);
}

function detectSecurity(files){
  const findings = [];
  const add = (severity, title, description, file, line, code) => {
    findings.push({ severity, title, description, file: basename(file), path: file, line, code });
  };
  safeArray(files).forEach((file) => {
    const text = String(file.content || '');
    const lines = text.split('\n');
    lines.forEach((line, i) => {
      if (/api[_-]?key|secret|password\s*=|token\s*=|-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----/i.test(line)) {
        add('high', 'Hardcoded Secret', 'Potential credential or secret detected in source code.', file.path, i + 1, line.trim());
      }
      if (/eval\s*\(/.test(line)) {
        add('medium', 'Dynamic Code Execution', 'Use of eval() can enable code execution vulnerabilities.', file.path, i + 1, line.trim());
      }
      if (/SELECT\s+.+\+\s*.+FROM|WHERE\s+.+\+\s*.+/i.test(line)) {
        add('high', 'SQL Injection Risk', 'Possible string-concatenated SQL query detected.', file.path, i + 1, line.trim());
      }
      if (/innerHTML\s*=/.test(line) && !/sanitize|DOMPurify/i.test(line)) {
        add('medium', 'XSS Vulnerability', 'innerHTML assignment without obvious sanitization.', file.path, i + 1, line.trim());
      }
    });
  });
  return findings.slice(0, 300);
}

function detectDuplicates(files){
  const byName = new Map();
  const output = [];
  safeArray(files).forEach((file) => {
    safeArray(file.functions).forEach((fn) => {
      const list = byName.get(fn.name) || [];
      list.push({ file: file.path, line: fn.line, name: fn.name });
      byName.set(fn.name, list);
    });
  });
  byName.forEach((entries, name) => {
    if (entries.length > 1) {
      output.push({
        type: 'name',
        name,
        count: entries.length,
        files: entries,
        suggestion: 'Rename or consolidate duplicate function names for clearer ownership.'
      });
    }
  });
  return output.slice(0, 200);
}

function calcComplexityScore(content){
  const text = String(content || '');
  const branches = (text.match(/\b(if|else if|for|while|switch|catch|case)\b/g) || []).length;
  const logicalOps = (text.match(/\&\&|\|\|/g) || []).length;
  return branches + logicalOps + 1;
}

function analyzeFiles(input, options = {}){
  const files = safeArray(input && input.files);
  const boundedFiles = files.slice(0, options.maxFiles || 300).map((f) => ({
    path: String(f.path || ''),
    content: String(f.content || '')
  }));
  const analyzed = [];
  const allFns = [];
  const functionUsage = new Map();
  const dependencies = [];
  const layerRank = { data: 0, services: 1, modules: 1, utils: 1, config: 1, ui: 2, test: 3 };

  boundedFiles.forEach((f) => {
    const ext = extOf(f.path);
    const isCode = CODE_EXTENSIONS.has(ext);
    const content = f.content.slice(0, options.maxFileBytes || 200000);
    const lines = content.split('\n').length;
    const funcs = isCode ? extractFunctions(content, f.path) : [];
    const layer = detectLayer(f.path);
    const complexity = calcComplexityScore(content);
    const item = {
      path: f.path,
      name: basename(f.path),
      folder: folderOf(f.path),
      content,
      functions: funcs,
      lines,
      layer,
      churn: 0,
      isCode,
      complexity
    };
    analyzed.push(item);
    funcs.forEach((fn) => {
      allFns.push({ ...fn, file: f.path, folder: item.folder, layer });
      functionUsage.set(
        fn.name,
        functionUsage.get(fn.name) || {
          internal: 0,
          external: 0,
          callers: [],
          file: f.path,
          folder: item.folder,
          line: fn.line,
          code: fn.code,
          isTopLevel: true,
          isExported: false,
          isClassMethod: false,
          type: 'function'
        }
      );
    });
  });

  const fnNames = [...new Set(allFns.map((f) => f.name))];
  analyzed.forEach((file) => {
    const text = file.content;
    fnNames.forEach((fnName) => {
      const regex = new RegExp(`\\b${fnName}\\s*\\(`, 'g');
      const matches = text.match(regex);
      const count = matches ? matches.length : 0;
      if (!count) return;
      const owner = functionUsage.get(fnName);
      if (!owner) return;
      if (owner.file === file.path) {
        owner.internal += count;
      } else {
        owner.external += count;
        owner.callers.push({ file: file.path, name: file.name, count });
        dependencies.push({ from: owner.file, to: file.path, function: fnName, callCount: count });
      }
    });
  });

  const deadFunctions = [];
  functionUsage.forEach((value, name) => {
    const total = value.internal + value.external;
    value.count = total;
    if (total === 0) {
      deadFunctions.push({ name, file: value.file, folder: value.folder, line: value.line, codeLines: value.code ? value.code.split('\n').length : 1, code: value.code, extension: extOf(value.file).slice(1) });
    }
  });

  const duplicates = detectDuplicates(analyzed);
  const securityIssues = detectSecurity(analyzed);
  const architectureIssues = [];

  const largeFiles = analyzed.filter((f) => f.functions.length > 15);
  if (largeFiles.length) {
    architectureIssues.push({
      type: 'critical',
      title: `${largeFiles.length} Large Files`,
      description: 'Files with more than 15 detected functions.',
      affectedFiles: largeFiles.map((f) => f.path),
      affectedItems: largeFiles.map((f) => ({ file: f.path, name: f.name, fns: f.functions.length, lines: f.lines }))
    });
  }
  if (deadFunctions.length) {
    architectureIssues.push({
      type: 'warning',
      title: `${deadFunctions.length} Unused Functions`,
      description: 'Functions with zero detected invocations.',
      affectedFiles: deadFunctions.map((f) => f.file),
      affectedItems: deadFunctions
    });
  }

  const layerViolations = dependencies
    .map((dep) => {
      const fromFile = analyzed.find((f) => f.path === dep.from);
      const toFile = analyzed.find((f) => f.path === dep.to);
      if (!fromFile || !toFile) return null;
      const fromRank = layerRank[fromFile.layer] ?? 1;
      const toRank = layerRank[toFile.layer] ?? 1;
      if (fromRank < toRank) {
        return {
          from: fromFile.path,
          to: toFile.path,
          fromLayer: fromFile.layer,
          toLayer: toFile.layer,
          fn: dep.function,
          suggestion: 'Refactor dependency direction to keep higher layers independent of lower ones.'
        };
      }
      return null;
    })
    .filter(Boolean)
    .slice(0, 200);

  const totalLoc = analyzed.reduce((sum, f) => sum + f.lines, 0);
  const languageMap = {};
  analyzed.forEach((f) => {
    const ext = extOf(f.path).replace('.', '') || 'unknown';
    languageMap[ext] = (languageMap[ext] || 0) + f.lines;
  });
  const languageBreakdown = Object.entries(languageMap)
    .sort((a, b) => b[1] - a[1])
    .map(([ext, lines]) => ({ ext, lines, pct: totalLoc ? Math.round((lines / totalLoc) * 100) : 0 }));

  const highSecurityIssues = securityIssues.filter((s) => s.severity === 'high').length;
  const summary = {
    healthScore: Math.max(0, 100 - Math.min(40, deadFunctions.length) - Math.min(30, highSecurityIssues * 5) - Math.min(20, layerViolations.length)),
    healthGrade: 'F',
    totalFiles: analyzed.length,
    totalFunctions: allFns.length,
    totalConnections: dependencies.length,
    linesOfCode: totalLoc,
    unusedFunctions: deadFunctions.length,
    securityIssues: securityIssues.length,
    patterns: 0,
    duplicates: duplicates.length,
    layerViolations: layerViolations.length,
    highSecurityIssues
  };
  summary.healthGrade = summary.healthScore >= 90 ? 'A' : summary.healthScore >= 80 ? 'B' : summary.healthScore >= 70 ? 'C' : summary.healthScore >= 60 ? 'D' : 'F';

  const fnStats = {};
  functionUsage.forEach((value, key) => {
    fnStats[key] = value;
  });

  const suggestions = [];
  if (highSecurityIssues > 0) {
    suggestions.push({
      priority: 'high',
      title: 'Prioritize security remediations',
      desc: `Resolve ${highSecurityIssues} high-severity security findings first.`,
      action: 'Create a security-focused remediation sprint for high-severity findings.',
      impact: 'Reduces immediate exploit risk.'
    });
  }
  if (deadFunctions.length > 0) {
    suggestions.push({
      priority: 'medium',
      title: 'Remove dead code',
      desc: `${deadFunctions.length} unused functions detected.`,
      action: 'Delete or archive unused functions after validating usage assumptions.',
      impact: 'Improves maintainability and lowers cognitive overhead.'
    });
  }
  if (layerViolations.length > 0) {
    suggestions.push({
      priority: 'high',
      title: 'Fix architecture direction',
      desc: `${layerViolations.length} layer violations detected.`,
      action: 'Refactor imports to preserve layer boundaries.',
      impact: 'Improves modularity and testability.'
    });
  }

  return {
    repository: input.repository || 'unknown',
    analyzedAt: new Date().toISOString(),
    codeflowVersion: '1.0',
    summary,
    files: analyzed.map((f) => ({
      path: f.path,
      name: f.name,
      folder: f.folder,
      layer: f.layer,
      lines: f.lines,
      churn: f.churn,
      isCode: f.isCode,
      functions: f.functions.map((fn) => ({
        name: fn.name,
        line: fn.line,
        internalCalls: fnStats[fn.name] ? fnStats[fn.name].internal : 0,
        externalCalls: fnStats[fn.name] ? fnStats[fn.name].external : 0,
        totalCalls: fnStats[fn.name] ? fnStats[fn.name].count : 0,
        isUnused: fnStats[fn.name] ? fnStats[fn.name].count === 0 : true,
        isExported: false,
        isClassMethod: false,
        isTopLevel: true,
        type: 'function',
        callers: fnStats[fn.name] ? fnStats[fn.name].callers : [],
        code: fn.code
      })),
      functionCount: f.functions.length
    })),
    unusedFunctions: deadFunctions,
    dependencies,
    architectureIssues,
    patterns: [],
    securityIssues,
    duplicates,
    layerViolations,
    suggestions,
    languageBreakdown,
    folderStructure: [...new Set(analyzed.map((f) => f.folder))].sort(),
    functionStatistics: Object.entries(fnStats).map(([name, st]) => ({
      name,
      file: st.file,
      folder: st.folder,
      line: st.line,
      internalCalls: st.internal,
      externalCalls: st.external,
      totalCalls: st.count,
      isExported: false,
      isClassMethod: false,
      isTopLevel: true,
      type: st.type,
      callers: st.callers,
      code: st.code
    }))
  };
}

module.exports = {
  analyzeFiles
};
