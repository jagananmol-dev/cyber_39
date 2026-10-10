const express = require('express');
const { isIP } = require('node:net');
const { randomUUID } = require('node:crypto');
const path = require('node:path');
const { analyzeTelemetry, captureBaseline, workloadKey } = require('./telemetry-engine');
const { StateStore, appendAudit, verifyAuditChain } = require('./state-store');

const PORT = Number(process.env.PORT) || 3000;
const HOST = '127.0.0.1';
const DATA_FILE = process.env.NCBA_DATA_FILE || path.join(__dirname, 'data', 'state.json');
const WORKLOAD_TYPES = new Set([
  'API Gateway', 'Partner Gateway', 'Internal Proxy', 'Legacy Auth Proxy',
  'Webhook Entry Point', 'Microservice', 'IoT Device'
]);
const EVENT_TYPES = new Set([
  'connection', 'authentication_failure', 'token_replay', 'certificate_expired',
  'certificate_mismatch', 'rate_anomaly', 'unexpected_egress',
  'threat_intelligence_match'
]);
const MAX_BATCH_SIZE = 1000;
const MAX_STORED_EVENTS = 10000;
const MINIMUM_BASELINE_EVENTS = 5;
const MAX_WORKLOADS = 1000;

function apiError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function normalizeEvent(input, index) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw apiError(400, 'INVALID_EVENT', `Event ${index + 1} must be a JSON object.`);
  }

  const workload = typeof input.workload === 'string' ? input.workload.trim() : '';
  if (!workload || workload.length > 80) {
    throw apiError(400, 'INVALID_WORKLOAD', `Event ${index + 1} requires a workload name of 1 to 80 characters.`);
  }

  if (
    typeof input.timestamp !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(input.timestamp)
  ) {
    throw apiError(400, 'INVALID_TIMESTAMP', `Event ${index + 1} requires an ISO 8601 timestamp.`);
  }
  const timestamp = new Date(input.timestamp);
  if (!Number.isFinite(timestamp.getTime())) {
    throw apiError(400, 'INVALID_TIMESTAMP', `Event ${index + 1} requires an ISO 8601 timestamp.`);
  }
  if (timestamp.getTime() > Date.now() + 5 * 60 * 1000) {
    throw apiError(400, 'FUTURE_TIMESTAMP', `Event ${index + 1} is more than five minutes in the future.`);
  }
  if (timestamp.getTime() < Date.now() - 90 * 24 * 60 * 60 * 1000) {
    throw apiError(400, 'STALE_TIMESTAMP', `Event ${index + 1} is more than 90 days old.`);
  }

  if (typeof input.eventType !== 'string' || !EVENT_TYPES.has(input.eventType)) {
    throw apiError(400, 'INVALID_EVENT_TYPE', `Event ${index + 1} has an unsupported eventType.`);
  }
  if (input.sourceIp != null && (typeof input.sourceIp !== 'string' || isIP(input.sourceIp) === 0)) {
    throw apiError(400, 'INVALID_SOURCE_IP', `Event ${index + 1} sourceIp must be a valid IPv4 or IPv6 address.`);
  }
  if (
    input.destination != null &&
    (typeof input.destination !== 'string' || !input.destination.trim() || input.destination.length > 128)
  ) {
    throw apiError(400, 'INVALID_DESTINATION', `Event ${index + 1} destination must contain 1 to 128 characters.`);
  }
  if (
    input.tlsFingerprint != null &&
    (typeof input.tlsFingerprint !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(input.tlsFingerprint))
  ) {
    throw apiError(400, 'INVALID_FINGERPRINT', `Event ${index + 1} tlsFingerprint contains invalid characters.`);
  }
  if (
    input.requestsPerMinute != null &&
    (!Number.isInteger(input.requestsPerMinute) || input.requestsPerMinute < 0 || input.requestsPerMinute > 1000000)
  ) {
    throw apiError(400, 'INVALID_REQUEST_RATE', `Event ${index + 1} requestsPerMinute must be an integer from 0 to 1,000,000.`);
  }
  if (
    input.type != null &&
    (typeof input.type !== 'string' || !WORKLOAD_TYPES.has(input.type))
  ) {
    throw apiError(400, 'INVALID_WORKLOAD_TYPE', `Event ${index + 1} has an unsupported workload type.`);
  }

  return {
    id: randomUUID(),
    workload,
    type: input.type || 'Microservice',
    timestamp: timestamp.toISOString(),
    eventType: input.eventType,
    sourceIp: input.sourceIp || null,
    destination: input.destination?.trim() || null,
    tlsFingerprint: input.tlsFingerprint || null,
    requestsPerMinute: input.requestsPerMinute ?? 0
  };
}

function validateBatch(body) {
  if (!body || typeof body !== 'object' || !Array.isArray(body.events)) {
    throw apiError(400, 'INVALID_BATCH', 'Send a JSON object containing an events array.');
  }
  if (body.events.length < 1 || body.events.length > MAX_BATCH_SIZE) {
    throw apiError(400, 'INVALID_BATCH_SIZE', `Each import must contain 1 to ${MAX_BATCH_SIZE} events.`);
  }
  return body.events.map(normalizeEvent);
}

function groupEvents(events) {
  const groups = new Map();
  for (const event of events) {
    const key = workloadKey(event.workload);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }
  return groups;
}

function validateGroupTypes(groups, state) {
  for (const [key, events] of groups) {
    const types = new Set(events.map(event => event.type));
    if (types.size !== 1) {
      throw apiError(400, 'MIXED_WORKLOAD_TYPES', 'A telemetry batch must use one workload type per workload name.');
    }
    const existing = state.entities.find(entity => workloadKey(entity.name) === key);
    if (existing && existing.type !== events[0].type) {
      throw apiError(409, 'WORKLOAD_TYPE_MISMATCH', `The workload type for "${existing.name}" differs from its saved inventory.`);
    }
  }
}

function ensureEntity(state, workload, type) {
  const key = workloadKey(workload);
  if (!state.entities) state.entities = [];
  let entity = state.entities.find(item => workloadKey(item.name) === key);
  if (!entity) {
    if (state.entities.length >= MAX_WORKLOADS) {
      throw apiError(409, 'WORKLOAD_LIMIT_REACHED', `The local monitor supports up to ${MAX_WORKLOADS} workloads.`);
    }
    entity = {
      id: `workload-${randomUUID()}`,
      name: workload,
      type,
      status: 'monitoring',
      createdAt: new Date().toISOString()
    };
    state.entities.push(entity);
  }
  return entity;
}

function createApp({ store = new StateStore(DATA_FILE) } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    let host;
    try {
      host = new URL(`http://${req.get('host')}`).hostname.toLowerCase();
    } catch {
      return res.status(400).json({ error: { code: 'INVALID_HOST', message: 'Use the local NCBA address.' } });
    }
    if (host !== '127.0.0.1' && host !== 'localhost') {
      return res.status(403).json({ error: { code: 'LOCAL_ONLY', message: 'NCBA accepts connections only through a local hostname.' } });
    }
    if (!['GET', 'HEAD'].includes(req.method) && req.get('origin')) {
      try {
        const origin = new URL(req.get('origin'));
        if (origin.protocol !== 'http:' || origin.host.toLowerCase() !== req.get('host').toLowerCase()) {
          return res.status(403).json({ error: { code: 'CROSS_ORIGIN_BLOCKED', message: 'Cross-origin state changes are not allowed.' } });
        }
      } catch {
        return res.status(403).json({ error: { code: 'INVALID_ORIGIN', message: 'State changes must come from the local NCBA page.' } });
      }
    }
    return next();
  });
  app.use(express.json({ limit: '1mb' }));

  app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.get('/styles.css', (_req, res) => res.sendFile(path.join(__dirname, 'styles.css')));
  app.get('/script.js', (_req, res) => res.sendFile(path.join(__dirname, 'script.js')));
  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

  app.get('/api/entities', (_req, res) => {
    const state = store.read();
    const entities = state.entities.filter(entity =>
      state.baselines[workloadKey(entity.name)]
    ).map(entity => {
      const baseline = state.baselines[workloadKey(entity.name)] || null;
      const latest = state.telemetry
        .filter(event => workloadKey(event.workload) === workloadKey(entity.name))
        .slice(-100);
      const assessment = baseline && latest.length ? analyzeTelemetry(latest, baseline) : null;
      return {
        id: entity.id,
        name: entity.name,
        type: entity.type,
        status: entity.status,
        createdAt: entity.createdAt,
        baseline: baseline ? {
          sampleCount: baseline.sampleCount,
          capturedAt: baseline.capturedAt
        } : null,
        assessment
      };
    });
    res.json(entities);
  });

  app.post('/api/telemetry/baselines', async (req, res, next) => {
    try {
      const events = validateBatch(req.body);
      const groups = groupEvents(events);
      validateGroupTypes(groups, store.read());
      for (const group of groups.values()) {
        if (group.length < MINIMUM_BASELINE_EVENTS) {
          throw apiError(400, 'INSUFFICIENT_BASELINE', `At least ${MINIMUM_BASELINE_EVENTS} baseline events are required per workload.`);
        }
      }

      const result = await store.update(state => {
        if (!state.baselines) state.baselines = {};
        const captured = [];
        for (const group of groups.values()) {
          const first = group[0];
          const entity = ensureEntity(state, first.workload, first.type);
          const key = workloadKey(first.workload);
          const baseline = captureBaseline(entity.name, group);
          state.baselines[key] = baseline;
          entity.status = 'monitoring';
          captured.push({ workload: entity.name, sampleCount: baseline.sampleCount });
        }
        appendAudit(state, 'telemetry_baseline_captured', null, { workloads: captured });
        return captured;
      });
      res.status(201).json({ baselines: result, minimumSamplesPerWorkload: MINIMUM_BASELINE_EVENTS });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/telemetry/ingest', async (req, res, next) => {
    try {
      const events = validateBatch(req.body);
      const groups = groupEvents(events);
      const currentState = store.read();
      validateGroupTypes(groups, currentState);
      const missing = [...groups.values()]
        .map(group => group[0].workload)
        .filter(workload => !currentState.baselines[workloadKey(workload)]);
      if (missing.length) {
        throw apiError(409, 'BASELINE_REQUIRED', `Capture a verified baseline before monitoring: ${missing.join(', ')}.`);
      }

      const result = await store.update(state => {
        const assessments = [];
        for (const group of groups.values()) {
          const first = group[0];
          const entity = ensureEntity(state, first.workload, first.type);
          const baseline = state.baselines[workloadKey(entity.name)];
          state.telemetry.push(...group);
          const recent = state.telemetry
            .filter(event => workloadKey(event.workload) === workloadKey(entity.name))
            .slice(-100);
          const assessment = analyzeTelemetry(recent, baseline);
          entity.assessment = assessment;
          entity.status = assessment.score >= 60 ? 'alert' : 'monitoring';
          assessments.push({
            workload: entity.name,
            ...assessment
          });
        }
        if (state.telemetry.length > MAX_STORED_EVENTS) {
          state.telemetry.splice(0, state.telemetry.length - MAX_STORED_EVENTS);
        }
        appendAudit(state, 'telemetry_batch_ingested', null, {
          eventCount: events.length,
          assessments: assessments.map(item => ({
            workload: item.workload,
            score: item.score,
            response: item.response
          }))
        });
        return assessments;
      });
      res.status(201).json({ assessments: result, storedEvents: events.length });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/telemetry', (req, res) => {
    const requestedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isInteger(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 500) : 50;
    const state = store.read();
    res.json({
      events: state.telemetry.slice(-limit).reverse(),
      total: state.telemetry.length,
      baselines: Object.values(state.baselines).map(baseline => ({
        workload: baseline.workload,
        sampleCount: baseline.sampleCount,
        capturedAt: baseline.capturedAt
      }))
    });
  });

  app.post('/api/telemetry/demo', async (_req, res, next) => {
    try {
      const now = Date.now();
      const workload = `Local incident drill ${new Date(now).toISOString().slice(0, 16)}`;
      const samples = Array.from({ length: 10 }, (_value, index) => ({
        workload,
        type: 'API Gateway',
        timestamp: new Date(now - (10 - index) * 60_000).toISOString(),
        eventType: 'connection',
        sourceIp: '192.0.2.10',
        destination: 'orders-api',
        tlsFingerprint: 'sha256:demo-baseline',
        requestsPerMinute: 20
      }));
      const capturedBaseline = captureBaseline(workload, samples);
      const observations = [
        {
          workload,
          type: 'API Gateway',
          timestamp: new Date(now - 6 * 60 * 60 * 1000).toISOString(),
          eventType: 'token_replay',
          sourceIp: '198.51.100.23',
          destination: 'orders-api',
          tlsFingerprint: 'sha256:unexpected-client',
          requestsPerMinute: 400
        },
        {
          workload,
          type: 'API Gateway',
          timestamp: new Date(now - 6 * 60 * 60 * 1000 + 30_000).toISOString(),
          eventType: 'threat_intelligence_match',
          sourceIp: '198.51.100.23',
          destination: 'admin-api',
          tlsFingerprint: 'sha256:unexpected-client',
          requestsPerMinute: 400
        }
      ].map(normalizeEvent);

      const assessment = await store.update(state => {
        if (!state.baselines) state.baselines = {};
        state.baselines[workloadKey(workload)] = capturedBaseline;
        const entity = ensureEntity(state, workload, 'API Gateway');
        state.telemetry.push(...observations);
        const result = analyzeTelemetry(observations, capturedBaseline);
        entity.assessment = result;
        entity.status = 'alert';
        appendAudit(state, 'local_incident_drill', entity.id, {
          synthetic: true,
          eventCount: observations.length,
          score: result.score,
          verdict: result.verdict
        });
        return result;
      });
      res.status(201).json({
        synthetic: true,
        notice: 'Synthetic training scenario only; not a live incident.',
        workload,
        assessment
      });
    } catch (error) {
      next(error);
    }
  });

  app.delete('/api/telemetry', async (_req, res, next) => {
    try {
      await store.update(state => {
        state.telemetry = [];
        state.baselines = {};
        state.entities = [];
        appendAudit(state, 'telemetry_and_baselines_cleared', null, {});
      });
      res.json({ cleared: true });
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
      return res.status(413).json({ error: { code: 'BODY_TOO_LARGE', message: 'Import must be no larger than 1 MB.' } });
    }
    const status = error.status || 500;
    if (status >= 500) console.error('Request failed:', error);
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
  return createApp({ store }).listen(PORT, HOST, () => {
    console.log(`NCBA local dashboard running at http://${HOST}:${PORT}`);
    console.log(`Local telemetry and baselines: ${DATA_FILE}`);
    console.log('Only processes on this computer can access the dashboard by default.');
  });
}

if (require.main === module) {
  start().catch(error => {
    console.error('Unable to start the NCBA dashboard:', error);
    process.exitCode = 1;
  });
}

module.exports = { createApp, normalizeEvent, validateBatch };
