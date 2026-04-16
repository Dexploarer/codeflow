# CodeFlow Agent API

CodeFlow now includes a backend API that turns CodeFlow analysis data into deterministic, machine-friendly outputs for agent workflows.

## Start the API

```bash
npm run start:api
```

Default server URL: `http://localhost:8787`

## API schema contract

- **Schema version:** `1.0.0`
- Deterministic `reportId`, finding IDs, and workflow task IDs
- Standardized sections:
  - `summary`
  - `findings.architecture`
  - `findings.security`
  - `findings.deadCode`
  - `findings.duplicates`
  - `findings.layerViolations`
  - `suggestions`

Every finding includes:
- `id`
- `category`
- `subtype`
- `severity`
- `priority`
- `title`
- `description`
- `targetFiles`

## Endpoints

### 1) Analyze input

`POST /api/v1/analyze`

Request:

```json
{
  "async": true,
  "input": {
    "kind": "codeflow-report | snapshot | github",
    "report": {},
    "files": [{ "path": "src/a.js", "content": "..." }],
    "repository": "owner/repo",
    "owner": "owner",
    "repo": "repo",
    "token": "ghp_xxx",
    "maxFiles": 200,
    "maxFileBytes": 120000
  }
}
```

Response (`202` async):

```json
{
  "jobId": "...",
  "status": "queued"
}
```

Response (`200` sync):

```json
{
  "jobId": "...",
  "status": "completed",
  "result": {
    "rawReport": {},
    "normalizedReport": {},
    "compactAgentReport": {},
    "actionableIssues": [],
    "workflow": {}
  }
}
```

### 2) Job status

`GET /api/v1/jobs/:jobId`

### 3) Normalized report

`GET /api/v1/jobs/:jobId/report`

### 4) Actionable issues

`GET /api/v1/jobs/:jobId/issues`

### 5) Workflow-ready remediation tasks

`GET /api/v1/jobs/:jobId/workflow`

### 6) Compact machine view

`GET /api/v1/jobs/:jobId/compact`

## Workflow generation strategy

Task bundles are ordered by category:
1. `security`
2. `architecture`
3. `maintainability`

Each task includes:
- `id`
- `findingId`
- `priority`, `severity`
- `targetFiles`
- `rationale`
- `acceptanceCriteria`
- `risk`
- `dependsOn`

## Auth, rate limiting, and reliability

- GitHub token format is validated before requests
- Retry on transient GitHub failures (`403`, `429`, `5xx`)
- Per-request bounds:
  - max files
  - max bytes per file
- API rate limiting per client IP
- Consistent JSON error responses for automation

## Migration from current browser export

Existing `generateReport()` output maps directly to `input.kind = "codeflow-report"`.

Migration path:
1. Export report JSON from browser UI (or send equivalent object)
2. POST it to `/api/v1/analyze`
3. Consume:
   - `/report` for normalized, stable schema
   - `/issues` for prioritizable findings
   - `/workflow` for ordered remediation tasks
