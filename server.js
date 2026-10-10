const express = require('express');
const { randomUUID } = require('node:crypto');
const path = require('node:path');
const { getCertificateStatus, getRiskAssessment } = require('./risk-engine');
const { StateStore, appendAudit, verifyAuditChain } = require('./state-store');

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = process.env.NCBA_DATA_FILE || path.join(__dirname, 'data', 'state.json');
const TYPES = new Set([
  'API Gateway',
  'Partner Gateway',
  'Internal Proxy',
  'Legacy Auth Proxy',
  'Webhook Entry Point',
  'Microservice',
  'IoT Device'
]);
const SCORE_FIELDS = [
  'behaviorAnomaly',
  'temporalDeviation',
  'peerVariance',
  'threatIntelligence'
];

function apiError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function validateEntityInput(input, { creating = false } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw apiError(400, 'INVALID_BODY', 'Request body must be a JSON object.');
  }

  const { name, type, certificateLifetimeHours, certificateAgeHours, agentInstalled } = input;
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 80) {
    throw apiError(400, 'INVALID_NAME', 'Name must contain 1 to 80 characters.');
  }
  if (typeof type !== 'string' || !TYPES.has(type)) {
    throw apiError(400, 'INVALID_TYPE', 'Select a supported workload type.');
  }
  if (!Number.isInteger(certificateLifetimeHours) || certificateLifetimeHours < 1 || certificateLifetimeHours > 24) {
    throw apiError(400, 'INVALID_CERTIFICATE_LIFETIME', 'Certificate lifetime must be an integer from 1 to 24 hours.');
  }
  if (
    !Number.isFinite(certificateAgeHours) ||
    certificateAgeHours < 0 ||
    certificateAgeHours > certificateLifetimeHours
  ) {
    throw apiError(400, 'INVALID_CERTIFICATE_AGE', 'Certificate age must be between zero and its lifetime.');
  }
  if (typeof agentInstalled !== 'boolean') {
    throw apiError(400, 'INVALID_AGENT_STATUS', 'Runtime agent status must be true or false.');
  }

  const entity = {
    name: name.trim(),
    type,
    certificateLifetimeHours,
    certificateAgeHours,
    agentInstalled
  };

  for (const field of SCORE_FIELDS) {
    if (!Number.isInteger(input[field]) || input[field] < 0 || input[field] > 100) {
      throw apiError(400, 'INVALID_SCORE', `${field} must be an integer from 0 to 100.`);
    }
    entity[field] = input[field];
  }

  if (!creating && (typeof input.id !== 'string' || !input.id.trim())) {
    throw apiError(400, 'INVALID_ENTITY_ID', 'An entity ID is required for analysis.');
  }

  return entity;
}

function enrichEntity(entity) {
  return {
    ...entity,
    ...getRiskAssessment(entity),
    certificate: getCertificateStatus(entity)
  };
}

function createApp({ store = new StateStore(DATA_FILE) } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));

  app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.get('/styles.css', (_req, res) => res.sendFile(path.join(__dirname, 'styles.css')));
  app.get('/script.js', (_req, res) => res.sendFile(path.join(__dirname, 'script.js')));

  app.get('/api/entities', (_req, res) => {
    const { entities } = store.read();
    res.json(entities.map(enrichEntity));
  });

  app.post('/api/entities', async (req, res, next) => {
    try {
      const input = validateEntityInput(req.body, { creating: true });
      const entity = await store.update(state => {
        const created = {
          id: `npe-${randomUUID()}`,
          ...input,
          status: 'active'
        };
        state.entities.unshift(created);
        appendAudit(state, 'entity_created', created.id, { name: created.name, type: created.type });
        return enrichEntity(created);
      });
      res.status(201).json(entity);
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/analyze', async (req, res, next) => {
    try {
      const input = validateEntityInput(req.body);
      const result = await store.update(state => {
        const entity = state.entities.find(item => item.id === req.body.id);
        if (!entity) {
          throw apiError(404, 'ENTITY_NOT_FOUND', 'The requested workload identity does not exist.');
        }

        Object.assign(entity, input);
        const certificate = getCertificateStatus(entity);
        if (entity.status === 'active' && certificate.renewalDue) {
          entity.certificateAgeHours = 0;
          appendAudit(state, 'certificate_renewed', entity.id, {
            lifetimeHours: entity.certificateLifetimeHours,
            renewalReason: 'Automatic renewal at 80% lifetime threshold'
          });
        }
        const assessment = enrichEntity(entity);
        appendAudit(state, 'risk_assessed', entity.id, {
          score: assessment.score,
          verdict: assessment.verdict,
          response: assessment.response
        });
        return assessment;
      });
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/entities/:id/actions', async (req, res, next) => {
    try {
      const { action, approvers } = req.body || {};
      const validActions = new Set(['revoke', 'isolate', 'restore', 'renew']);
      if (!validActions.has(action)) {
        throw apiError(400, 'INVALID_ACTION', 'Action must be revoke, isolate, restore, or renew.');
      }

      if (action !== 'renew') {
        if (
          !Array.isArray(approvers) ||
          approvers.length !== 2 ||
          approvers.some(name => typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60) ||
          new Set(approvers.map(name => name.trim().toLowerCase())).size !== 2
        ) {
          throw apiError(400, 'INVALID_APPROVALS', 'Provide two different approver names (2-of-3 demo approval).');
        }
      }

      const result = await store.update(state => {
        const entity = state.entities.find(item => item.id === req.params.id);
        if (!entity) {
          throw apiError(404, 'ENTITY_NOT_FOUND', 'The requested workload identity does not exist.');
        }

        if (action === 'renew') {
          if (entity.status !== 'active') {
            throw apiError(409, 'ENTITY_NOT_ACTIVE', 'Only active workload identities can be renewed.');
          }
          entity.certificateAgeHours = 0;
          appendAudit(state, 'certificate_renewed', entity.id, {
            lifetimeHours: entity.certificateLifetimeHours,
            renewalReason: 'Manual demonstration action'
          });
          return { entity: enrichEntity(entity), message: 'Certificate renewed; its age is now zero hours.' };
        }

        const statuses = {
          revoke: 'revoked',
          isolate: 'isolated',
          restore: 'active'
        };
        if (action === 'restore' && entity.status === 'active') {
          throw apiError(409, 'ENTITY_ALREADY_ACTIVE', 'This workload identity is already active.');
        }
        if (action === 'revoke' && entity.status === 'revoked') {
          throw apiError(409, 'ENTITY_ALREADY_REVOKED', 'This workload identity has already been revoked.');
        }
        if (action === 'isolate' && entity.status === 'isolated') {
          throw apiError(409, 'ENTITY_ALREADY_ISOLATED', 'This workload identity has already been isolated.');
        }

        entity.status = statuses[action];
        appendAudit(state, `${action}_approved`, entity.id, {
          approvers: approvers.map(name => name.trim()),
          quorum: '2-of-3 demonstration approval'
        });
        return {
          entity: enrichEntity(entity),
          message: `${action[0].toUpperCase()}${action.slice(1)} action applied after two distinct demo approvals.`
        };
      });
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/audit', (req, res) => {
    const requestedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isInteger(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 100) : 20;
    const { audit } = store.read();
    res.json({ events: audit.slice(-limit).reverse(), total: audit.length });
  });

  app.get('/api/audit/verify', (_req, res) => {
    const { audit } = store.read();
    res.json(verifyAuditChain(audit));
  });

  app.use((req, _res, next) => next(apiError(404, 'NOT_FOUND', `No route for ${req.method} ${req.path}.`)));

  app.use((error, _req, res, _next) => {
    if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
      return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'Request body contains invalid JSON.' } });
    }
    if (error.type === 'entity.too.large') {
      return res.status(413).json({ error: { code: 'BODY_TOO_LARGE', message: 'Request body must be no larger than 16 KB.' } });
    }
    const status = error.status || 500;
    if (status >= 500) {
      console.error('Request failed:', error);
    }
    return res.status(status).json({
      error: {
        code: error.code || 'INTERNAL_ERROR',
        message: status >= 500 ? 'An unexpected server error occurred.' : error.message
      }
    });
  });

  return app;
}

async function start() {
  const store = new StateStore(DATA_FILE);
  await store.initialize();
  return createApp({ store }).listen(PORT, () => {
    console.log(`NCBA dashboard running at http://localhost:${PORT}`);
    console.log(`Local demonstration data: ${DATA_FILE}`);
  });
}

if (require.main === module) {
  start().catch(error => {
    console.error('Unable to start the NCBA dashboard:', error);
    process.exitCode = 1;
  });
}

module.exports = { createApp, validateEntityInput };
