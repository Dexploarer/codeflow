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

## v2 Agent Contract

Versioned coding-agent routes now live under `/api/v2`.

### Envelope format (all v2 responses)

```json
{
  "meta": {
    "requestId": "uuid",
    "schemaVersion": "1.0.0",
    "jobId": "optional-job-id",
    "cacheKey": "optional-stable-cache-key",
    "pageInfo": null,
    "analysisWarnings": []
  },
  "data": {},
  "errors": []
}
```

### Discovery

- `GET /api/v2/capabilities`
- `GET /api/v2/schema`

### Repository grasp

- `GET /api/v2/agent/:jobId/overview`
- `GET /api/v2/agent/:jobId/map`
- `GET /api/v2/agent/:jobId/hotspots?page=1&pageSize=25`
- `GET /api/v2/agent/:jobId/dependencies?file=src/a.js&layer=services&direction=both&depth=2&page=1&pageSize=25`

### Sanity and quality checks

- `GET /api/v2/agent/:jobId/sanity`
- `GET /api/v2/agent/:jobId/quality-gates?highSeverityMax=0&layerViolationMax=5`
- `GET /api/v2/agent/:jobId/coverage`

### Remediation planning

- `GET /api/v2/agent/:jobId/plan`
- `GET /api/v2/agent/:jobId/checklists`
- `GET /api/v2/agent/:jobId/change-impact?files=src/a.js,src/b.js`

### Slop-reduced agent context

- `GET /api/v2/agent/:jobId/context?maxItems=5`
  - Returns a bounded high-signal packet with summary, critical signals, next actions, and agent cleanup intelligence.
  - Includes agent-ready sections:
    - `agentCleanup.slopCandidates` (highest-noise files to clean first)
    - `agentCleanup.logicMistakes` (likely logic/boundary/security mistakes)
    - `agentCleanup.complexityHotspots` (overly complex files)
    - `agentCleanup.refactorOpportunities` (highest-value refactors)
  - `maxItems` must be an integer between 1 and 25 (default: 5).
  - Includes explicit truncation metadata so agents can request more detail when needed.

### Reliability & auth notes

- `POST /api/v1/analyze` accepts an idempotency key via `Idempotency-Key` header or `idempotencyKey` body field.
- Completed jobs expose stable `cacheKey` metadata in v2 responses.
- Optional signed polling token support can be enabled with `CODEFLOW_JOB_TOKEN_SECRET`.
- Optional scoped auth:
  - `CODEFLOW_API_READ_TOKEN` for v2 read routes.
  - `CODEFLOW_API_ADMIN_TOKEN` for `/api/v2/admin/config`.
- Structured error codes include: `INVALID_INPUT`, `INCOMPLETE_ANALYSIS`, `RATE_LIMITED`, `JOB_NOT_FOUND`, `FORBIDDEN`, `NOT_FOUND`.

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
