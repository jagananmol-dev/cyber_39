const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const EMPTY_HASH = '0'.repeat(64);

function createInitialState() {
  return {
    schemaVersion: 1,
    entities: [
      {
        id: 'npe-001',
        name: 'Public API Gateway',
        type: 'API Gateway',
        certificateLifetimeHours: 24,
        certificateAgeHours: 19.2,
        agentInstalled: true,
        behaviorAnomaly: 72,
        temporalDeviation: 68,
        peerVariance: 75,
        threatIntelligence: 60,
        status: 'active'
      },
      {
        id: 'npe-002',
        name: 'Partner Portal Edge',
        type: 'Partner Gateway',
        certificateLifetimeHours: 12,
        certificateAgeHours: 4,
        agentInstalled: false,
        behaviorAnomaly: 42,
        temporalDeviation: 38,
        peerVariance: 35,
        threatIntelligence: 25,
        status: 'active'
      },
      {
        id: 'npe-003',
        name: 'Internal Admin Proxy',
        type: 'Internal Proxy',
        certificateLifetimeHours: 6,
        certificateAgeHours: 2,
        agentInstalled: true,
        behaviorAnomaly: 18,
        temporalDeviation: 16,
        peerVariance: 14,
        threatIntelligence: 10,
        status: 'active'
      },
      {
        id: 'npe-004',
        name: 'Legacy Payment Gateway',
        type: 'Legacy Auth Proxy',
        certificateLifetimeHours: 24,
        certificateAgeHours: 22,
        agentInstalled: false,
        behaviorAnomaly: 96,
        temporalDeviation: 92,
        peerVariance: 88,
        threatIntelligence: 90,
        status: 'active'
      }
    ],
    audit: []
  };
}

function hashAuditEvent(event) {
  const payload = {
    id: event.id,
    timestamp: event.timestamp,
    type: event.type,
    entityId: event.entityId,
    details: event.details,
    previousHash: event.previousHash
  };

  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

function appendAudit(state, type, entityId, details) {
  const previousHash = state.audit.length
    ? state.audit[state.audit.length - 1].hash
    : EMPTY_HASH;
  const event = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    type,
    entityId,
    details,
    previousHash
  };

  event.hash = hashAuditEvent(event);
  state.audit.push(event);
  return event;
}

function verifyAuditChain(events) {
  let previousHash = EMPTY_HASH;

  for (const event of events) {
    if (event.previousHash !== previousHash || event.hash !== hashAuditEvent(event)) {
      return { valid: false, checked: events.indexOf(event) + 1 };
    }
    previousHash = event.hash;
  }

  return { valid: true, checked: events.length };
}

class StateStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.state = null;
    this.writeQueue = Promise.resolve();
  }

  async initialize() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });

    try {
      const raw = await fs.readFile(this.filePath, 'utf8');
      const state = JSON.parse(raw);
      if (
        state.schemaVersion !== 1 ||
        !Array.isArray(state.entities) ||
        !Array.isArray(state.audit)
      ) {
        throw new Error('State file has an unsupported or invalid format.');
      }
      this.state = state;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw new Error(`Unable to load NCBA state from ${this.filePath}: ${error.message}`, { cause: error });
      }
      this.state = createInitialState();
      await this.persist(this.state);
    }
  }

  read() {
    if (!this.state) {
      throw new Error('State store has not been initialized.');
    }
    return structuredClone(this.state);
  }

  update(mutator) {
    const operation = this.writeQueue.then(async () => {
      if (!this.state) {
        throw new Error('State store has not been initialized.');
      }

      const nextState = structuredClone(this.state);
      const result = mutator(nextState);
      await this.persist(nextState);
      this.state = nextState;
      return structuredClone(result);
    });

    this.writeQueue = operation.catch(() => {});
    return operation;
  }

  async persist(state) {
    const temporaryPath = `${this.filePath}.tmp`;
    await fs.writeFile(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
    await fs.rename(temporaryPath, this.filePath);
  }
}

module.exports = { StateStore, appendAudit, verifyAuditChain };
