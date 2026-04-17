const crypto = require('crypto');

class JobStore {
  constructor() {
    this.jobs = new Map();
    this.idempotencyIndex = new Map();
  }

  create(payload = {}, options = {}) {
    const idempotencyKey = options.idempotencyKey ? String(options.idempotencyKey) : '';
    if (idempotencyKey) {
      const existingId = this.idempotencyIndex.get(idempotencyKey);
      if (existingId) {
        const existing = this.jobs.get(existingId);
        if (existing) return existing;
      }
    }
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const job = {
      id,
      status: 'queued',
      createdAt: now,
      updatedAt: now,
      error: null,
      input: payload,
      idempotencyKey: idempotencyKey || null,
      result: null
    };
    this.jobs.set(id, job);
    if (idempotencyKey) {
      this.idempotencyIndex.set(idempotencyKey, id);
    }
    return job;
  }

  get(id) {
    return this.jobs.get(id) || null;
  }

  update(id, patch = {}) {
    const existing = this.jobs.get(id);
    if (!existing) return null;
    const updated = Object.assign({}, existing, patch, { updatedAt: new Date().toISOString() });
    this.jobs.set(id, updated);
    return updated;
  }
}

module.exports = {
  JobStore
};
