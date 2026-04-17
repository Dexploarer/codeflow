const https = require('https');

function isValidTokenFormat(token){
  if(!token) return true;
  return /^(ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)$/.test(token);
}

function requestJson(url, options = {}){
  const method = options.method || 'GET';
  const timeoutMs = options.timeoutMs || 10000;
  const headers = Object.assign(
    {
      'User-Agent': 'codeflow-agent-api',
      'Accept': 'application/vnd.github+json'
    },
    options.headers || {}
  );
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers, timeout: timeoutMs }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        const statusCode = res.statusCode || 500;
        if (statusCode < 200 || statusCode >= 300) {
          let message = `GitHub API request failed with status ${statusCode}`;
          try {
            const parsed = JSON.parse(data);
            if (parsed && parsed.message) message = parsed.message;
          } catch (_err) {}
          reject(Object.assign(new Error(message), { statusCode }));
          return;
        }
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error(`Failed to parse GitHub API response: ${err.message}`));
        }
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error('GitHub API request timed out'));
    });
    req.on('error', reject);
    req.end();
  });
}

async function withRetry(run, retries = 2){
  let lastError;
  for (let i = 0; i <= retries; i += 1) {
    try {
      return await run();
    } catch (err) {
      lastError = err;
      const status = err && err.statusCode;
      const retryable = status === 403 || status === 429 || status >= 500;
      if (!retryable || i === retries) break;
      await new Promise((resolve) => setTimeout(resolve, (i + 1) * 300));
    }
  }
  throw lastError;
}

function createHeaders(token){
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function fetchRepoFiles(owner, repo, options = {}){
  const token = options.token || '';
  const maxFiles = Math.max(1, Math.min(500, options.maxFiles || 200));
  const maxFileBytes = Math.max(1024, Math.min(250000, options.maxFileBytes || 120000));
  const includeExtensions = options.includeExtensions || null;

  if (!owner || !repo) throw new Error('owner and repo are required');
  if (!isValidTokenFormat(token)) {
    const err = new Error('Invalid GitHub token format.');
    err.statusCode = 400;
    throw err;
  }

  const headers = createHeaders(token);
  const repoInfo = await withRetry(() => requestJson(`https://api.github.com/repos/${owner}/${repo}`, { headers }));
  const tree = await withRetry(() => requestJson(`https://api.github.com/repos/${owner}/${repo}/git/trees/${repoInfo.default_branch}?recursive=1`, { headers }));
  const blobs = (Array.isArray(tree.tree) ? tree.tree : [])
    .filter((node) => node.type === 'blob')
    .filter((node) => !node.path.includes('node_modules/') && !node.path.includes('.git/') && !node.path.includes('dist/'))
    .filter((node) => node.size <= maxFileBytes)
    .filter((node) => !includeExtensions || includeExtensions.some((ext) => node.path.endsWith(ext)))
    .slice(0, maxFiles);
  const candidateBlobCount = (Array.isArray(tree.tree) ? tree.tree : [])
    .filter((node) => node.type === 'blob')
    .filter((node) => !node.path.includes('node_modules/') && !node.path.includes('.git/') && !node.path.includes('dist/')).length;

  const files = [];
  let truncatedByBytes = 0;
  for (let i = 0; i < blobs.length; i += 1) {
    const blob = blobs[i];
    const blobData = await withRetry(() => requestJson(`https://api.github.com/repos/${owner}/${repo}/git/blobs/${blob.sha}`, { headers }));
    const content = blobData && blobData.content ? Buffer.from(blobData.content, 'base64').toString('utf8') : '';
    if (content.length > maxFileBytes) truncatedByBytes += 1;
    files.push({ path: blob.path, content: content.slice(0, maxFileBytes) });
  }

  return {
    repository: `${owner}/${repo}`,
    defaultBranch: repoInfo.default_branch,
    files,
    sourceMeta: {
      candidateFiles: candidateBlobCount,
      fetchedFiles: files.length,
      skippedByMaxFiles: Math.max(0, candidateBlobCount - files.length),
      skippedByMaxFileBytes: Math.max(0, candidateBlobCount - blobs.length),
      truncatedByBytes
    }
  };
}

module.exports = {
  isValidTokenFormat,
  fetchRepoFiles
};
