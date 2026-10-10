const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createApp } = require('../server');
const { StateStore } = require('../state-store');
const { getRiskAssessment } = require('../risk-engine');
const { analyzeTelemetry, captureBaseline } = require('../telemetry-engine');

function makeEvents(workload, count, overrides = {}) {
  const now = Date.now();
  return Array.from({ length: count }, (_value, index) => ({
    workload,
    type: 'API Gateway',
    timestamp: new Date(now - (count - index) * 60_000).toISOString(),
    eventType: 'connection',
    sourceIp: '192.0.2.10',
    destination: 'orders-api',
    tlsFingerprint: 'sha256:known-good',
    requestsPerMinute: 20,
    ...overrides
  }));
}

async function startTestServer(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ncba-test-'));
  const statePath = path.join(directory, 'state.json');
  const store = new StateStore(statePath);
  await store.initialize();
  const server = createApp({ store }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await fs.rm(directory, { recursive: true, force: true });
  });
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    store,
    statePath
  };
}

async function jsonRequest(origin, route, body, method = 'POST') {
  const response = await fetch(`${origin}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  return { response, data: await response.json() };
}

test('risk policy uses stable weights and documented decision thresholds', () => {
  for (const score of [0, 29, 30, 59, 60, 84, 85, 100]) {
    const result = getRiskAssessment({
      behaviorAnomaly: score,
      temporalDeviation: score,
      peerVariance: score,
      threatIntelligence: score
    });
    assert.equal(result.score, score);
    assert.equal(result.response,
      score < 30 ? 'Allow and monitor'
        : score < 60 ? 'Step-up verification'
          : score < 85 ? 'Throttle / investigate'
            : 'Containment review');
  }
});

test('telemetry compares observable behavior to a known-good workload baseline', () => {
  const baseline = captureBaseline('orders-api', makeEvents('orders-api', 10));
  const observations = [
    {
      ...makeEvents('orders-api', 1, {
        eventType: 'token_replay',
        sourceIp: '198.51.100.23',
        tlsFingerprint: 'sha256:unfamiliar',
        requestsPerMinute: 400
      })[0]
    },
    {
      ...makeEvents('orders-api', 1, {
        eventType: 'threat_intelligence_match',
        sourceIp: '198.51.100.23',
        destination: 'admin-api',
        tlsFingerprint: 'sha256:unfamiliar',
        requestsPerMinute: 400
      })[0]
    }
  ];
  const assessment = analyzeTelemetry(observations, baseline);
  assert.equal(assessment.factors.behaviorAnomaly, 100);
  assert.equal(assessment.factors.peerVariance, 83);
  assert.equal(assessment.factors.threatIntelligence, 100);
  assert.equal(assessment.verdict, 'Critical Risk');
  assert.equal(assessment.evidence.novelDestinationEvents, 1);
  assert.equal(assessment.evidence.novelFingerprintEvents, 2);
  assert.equal(assessment.confidence, 'Low');
});

test('local API captures a baseline, rejects unbaselined and invalid telemetry, and records assessed evidence', async t => {
  const { origin, store, statePath } = await startTestServer(t);
  const baseline = makeEvents('payments-api', 10);

  const rejectedObservation = await jsonRequest(origin, '/api/telemetry/ingest', {
    events: makeEvents('unknown-api', 1)
  });
  assert.equal(rejectedObservation.response.status, 409);
  assert.equal(rejectedObservation.data.error.code, 'BASELINE_REQUIRED');

  const insufficientBaseline = await jsonRequest(origin, '/api/telemetry/baselines', {
    events: makeEvents('payments-api', 4)
  });
  assert.equal(insufficientBaseline.response.status, 400);
  assert.equal(insufficientBaseline.data.error.code, 'INSUFFICIENT_BASELINE');

  const invalidEvent = await jsonRequest(origin, '/api/telemetry/baselines', {
    events: baseline.map((event, index) => index === 0
      ? { ...event, sourceIp: 'not-an-ip' }
      : event)
  });
  assert.equal(invalidEvent.response.status, 400);
  assert.equal(invalidEvent.data.error.code, 'INVALID_SOURCE_IP');
  assert.equal(store.read().entities.length, 0);

  const baselineResponse = await jsonRequest(origin, '/api/telemetry/baselines', { events: baseline });
  assert.equal(baselineResponse.response.status, 201);
  assert.equal(baselineResponse.data.baselines[0].sampleCount, 10);

  const observations = [
    ...makeEvents('payments-api', 1, {
      eventType: 'token_replay',
      sourceIp: '198.51.100.23',
      tlsFingerprint: 'sha256:unfamiliar',
      requestsPerMinute: 400
    }),
    ...makeEvents('payments-api', 1, {
      eventType: 'threat_intelligence_match',
      sourceIp: '198.51.100.23',
      destination: 'admin-api',
      tlsFingerprint: 'sha256:unfamiliar',
      requestsPerMinute: 400
    })
  ];
  const ingestion = await jsonRequest(origin, '/api/telemetry/ingest', { events: observations });
  assert.equal(ingestion.response.status, 201);
  assert.equal(ingestion.data.assessments[0].verdict, 'Critical Risk');

  const entityList = await fetch(`${origin}/api/entities`).then(response => response.json());
  assert.equal(entityList.length, 1);
  assert.equal(entityList[0].assessment.score, ingestion.data.assessments[0].score);
  assert.equal(entityList[0].baseline.sampleCount, 10);

  const auditStatus = await fetch(`${origin}/api/audit/verify`).then(response => response.json());
  assert.deepEqual(auditStatus, { valid: true, checked: 2 });
  const persisted = JSON.parse(await fs.readFile(statePath, 'utf8'));
  assert.equal(persisted.telemetry.length, 2);
  assert.equal(persisted.audit.length, 2);
});

test('local incident drill is explicitly synthetic and clearing removes data but retains audit', async t => {
  const { origin } = await startTestServer(t);
  const drill = await jsonRequest(origin, '/api/telemetry/demo', {});
  assert.equal(drill.response.status, 201);
  assert.equal(drill.data.synthetic, true);
  assert.ok(drill.data.assessment.score >= 85);

  const cleared = await jsonRequest(origin, '/api/telemetry', undefined, 'DELETE');
  assert.equal(cleared.response.status, 200);
  assert.equal(cleared.data.cleared, true);
  assert.deepEqual(await fetch(`${origin}/api/entities`).then(response => response.json()), []);
  assert.deepEqual(await fetch(`${origin}/api/telemetry/`).then(response => response.json()).then(data => data.total), 0);
  assert.deepEqual(await fetch(`${origin}/api/audit/verify`).then(response => response.json()), { valid: true, checked: 2 });
});

test('state-changing requests reject cross-origin browser attempts', async t => {
  const { origin } = await startTestServer(t);
  const response = await fetch(`${origin}/api/telemetry/demo`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: 'http://attacker.example'
    },
    body: '{}'
  });
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, 'CROSS_ORIGIN_BLOCKED');
  assert.deepEqual(await fetch(`${origin}/api/audit/verify`).then(result => result.json()), {
    valid: true,
    checked: 0
  });
});

test('state store migrates existing local version-one data without inventing baselines', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ncba-migration-test-'));
  const statePath = path.join(directory, 'state.json');
  const state = {
    schemaVersion: 1,
    entities: [{ id: 'legacy', name: 'Legacy API', type: 'API Gateway', status: 'active' }],
    audit: []
  };
  await fs.writeFile(statePath, JSON.stringify(state), 'utf8');
  t.after(() => fs.rm(directory, { recursive: true, force: true }));

  const store = new StateStore(statePath);
  await store.initialize();
  const migrated = store.read();
  assert.equal(migrated.schemaVersion, 2);
  assert.equal(migrated.entities[0].name, 'Legacy API');
  assert.deepEqual(migrated.baselines, {});
  assert.deepEqual(migrated.telemetry, []);
  assert.equal(JSON.parse(await fs.readFile(statePath, 'utf8')).schemaVersion, 2);
});
