const crypto = require('crypto');

class JobStore {
  constructor() {
    this.jobs = new Map();
  }

  create(payload = {}) {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const job = {
      id,
      status: 'queued',
      createdAt: now,
      updatedAt: now,
      error: null,
      input: payload,
      result: null
    };
    this.jobs.set(id, job);
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
