const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createApp } = require('../server');
const { StateStore } = require('../state-store');
const { getCertificateStatus, getRiskAssessment } = require('../risk-engine');

test('risk assessment uses the documented weights and policy tiers', () => {
  for (const score of [0, 29, 30, 59, 60, 84, 85, 100]) {
    const result = getRiskAssessment({
      behaviorAnomaly: score,
      temporalDeviation: score,
      peerVariance: score,
      threatIntelligence: score
    });
    assert.equal(result.score, score);
    assert.equal(result.response,
      score < 30 ? 'Allow'
        : score < 60 ? 'Challenge'
          : score < 85 ? 'Throttle'
            : 'Block');
  }
  assert.equal(getCertificateStatus({
    certificateLifetimeHours: 10,
    certificateAgeHours: 8
  }).renewalDue, true);
});

test('API validates input, persists analysis, and records verifiable response actions', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ncba-test-'));
  const store = new StateStore(path.join(directory, 'state.json'));
  await store.initialize();
  const server = createApp({ store }).listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await fs.rm(directory, { recursive: true, force: true });
  });

  const entitiesResponse = await fetch(`${origin}/api/entities`);
  assert.equal(entitiesResponse.status, 200);
  const entities = await entitiesResponse.json();
  assert.equal(entities.length, 4);

  const invalidResponse = await fetch(`${origin}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: entities[0].id, name: 'bad', type: 'API Gateway' })
  });
  assert.equal(invalidResponse.status, 400);

  const target = entities[0];
  const analysisResponse = await fetch(`${origin}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: target.id,
      name: target.name,
      type: target.type,
      certificateLifetimeHours: target.certificateLifetimeHours,
      certificateAgeHours: target.certificateAgeHours,
      agentInstalled: target.agentInstalled,
      behaviorAnomaly: 100,
      temporalDeviation: 100,
      peerVariance: 100,
      threatIntelligence: 100
    })
  });
  assert.equal(analysisResponse.status, 200);
  const analysis = await analysisResponse.json();
  assert.equal(analysis.response, 'Block');
  assert.equal(analysis.certificate.ageHours, 0);
  assert.equal(analysis.certificate.renewalDue, false);

  const duplicateApproverResponse = await fetch(`${origin}/api/entities/${target.id}/actions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'revoke', approvers: ['analyst-a', 'ANALYST-A'] })
  });
  assert.equal(duplicateApproverResponse.status, 400);

  const actionResponse = await fetch(`${origin}/api/entities/${target.id}/actions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'revoke', approvers: ['analyst-a', 'analyst-b'] })
  });
  assert.equal(actionResponse.status, 200);
  assert.equal((await actionResponse.json()).entity.status, 'revoked');

  const auditResponse = await fetch(`${origin}/api/audit/verify`);
  assert.deepEqual(await auditResponse.json(), { valid: true, checked: 3 });
  const persisted = JSON.parse(await fs.readFile(path.join(directory, 'state.json'), 'utf8'));
  assert.equal(persisted.entities[0].status, 'revoked');
  assert.equal(persisted.audit.length, 3);
  assert.equal(persisted.audit[0].type, 'certificate_renewed');
});
