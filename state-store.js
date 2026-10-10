const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const EMPTY_HASH = '0'.repeat(64);

function createInitialState() {
  return {
    schemaVersion: 2,
    entities: [],
    baselines: {},
    telemetry: [],
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
      if (![1, 2].includes(state.schemaVersion) ||
        !Array.isArray(state.entities) ||
        !Array.isArray(state.audit)) {
        throw new Error('State file has an unsupported or invalid format.');
      }
      const version = state.schemaVersion;
      state.schemaVersion = 2;
      state.baselines ||= {};
      state.telemetry ||= [];
      if (Array.isArray(state.baselines) || typeof state.baselines !== 'object') {
        throw new Error('State file baselines must be an object.');
      }
      if (!Array.isArray(state.telemetry)) {
        throw new Error('State file telemetry must be an array.');
      }
      this.state = state;
      if (version !== 2) {
        await this.persist(state);
      }
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
