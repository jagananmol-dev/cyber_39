const entityList = document.getElementById('entityList');
const riskRing = document.getElementById('riskRing');
const verdictBox = document.getElementById('verdictBox');
const insightsList = document.getElementById('insightsList');
const riskChart = document.getElementById('riskChart');
const intakeMessage = document.getElementById('intakeMessage');

let entities = [];
let selectedEntityId = null;
let objectUrls = [];

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers }
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error?.message || `Request failed (${response.status}).`);
  return result;
}

function getRisk(score) {
  if (score >= 85) return { verdict: 'Critical', color: '#ff6679' };
  if (score >= 60) return { verdict: 'High', color: '#ff8a65' };
  if (score >= 30) return { verdict: 'Moderate', color: '#f7bf5d' };
  return { verdict: 'Low', color: '#6ee7a8' };
}

function showMessage(message, isError = false) {
  intakeMessage.textContent = message;
  intakeMessage.dataset.error = String(isError);
}

function renderEntities() {
  entityList.innerHTML = entities.map(entity => {
    const score = entity.assessment?.score;
    const risk = score == null ? { verdict: 'Baselined', color: '#76d5ff' } : getRisk(score);
    const riskType = score == null ? 'baseline'
      : score >= 85 ? 'critical'
        : score >= 60 ? 'high'
          : score >= 30 ? 'medium' : 'low';
    return `<button class="entity-card ${entity.id === selectedEntityId ? 'active' : ''}" data-id="${escapeHtml(entity.id)}" data-risk="${riskType}" type="button">
      <span class="entity-top"><span class="entity-name">${escapeHtml(entity.name)}</span><span class="entity-chip">${risk.verdict}${score == null ? '' : ` · ${score}`}</span></span>
      <span class="entity-meta"><span>${escapeHtml(entity.type)} · ${entity.baseline?.sampleCount || 0} baseline events</span><span>${score == null ? 'Awaiting observations' : 'Assessed'}</span></span>
    </button>`;
  }).join('');

  for (const card of entityList.querySelectorAll('.entity-card')) {
    card.addEventListener('click', () => {
      selectedEntityId = card.dataset.id;
      renderEntities();
      renderSelected();
    });
  }

  document.getElementById('emptyInventory').hidden = entities.length > 0;
  document.getElementById('kpiEntities').textContent = entities.length;
  document.getElementById('kpiHighRisk').textContent =
    entities.filter(entity => entity.assessment?.score >= 60).length;
}

function renderSelected() {
  const entity = entities.find(item => item.id === selectedEntityId);
  const assessment = entity?.assessment;
  document.getElementById('selectedWorkload').textContent = entity
    ? `${entity.name} · baseline ${entity.baseline.sampleCount} events`
    : 'No workload selected';

  if (!assessment) {
    document.getElementById('riskScore').textContent = '—';
    riskRing.style.background = 'conic-gradient(rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.04) 0)';
    document.getElementById('confidenceLabel').textContent = entity ? 'Awaiting observations' : 'Waiting for data';
    verdictBox.innerHTML = entity
      ? '<h3>Baseline captured</h3><p>Import new observations for this workload to evaluate behavior against its baseline.</p>'
      : '<h3>Ready for telemetry</h3><p>Capture a verified baseline and import new observations. No risk score is invented when data is missing.</p>';
    insightsList.replaceChildren();
    document.getElementById('evidenceBox').replaceChildren();
    renderChart({ behaviorAnomaly: 0, temporalDeviation: 0, peerVariance: 0, threatIntelligence: 0 });
    return;
  }

  const risk = getRisk(assessment.score);
  document.getElementById('riskScore').textContent = assessment.score;
  riskRing.style.background = `conic-gradient(${risk.color} ${assessment.score}%, rgba(255,255,255,0.04) 0)`;
  document.getElementById('confidenceLabel').textContent = `${assessment.confidence} confidence`;
  verdictBox.innerHTML = `<h3>${risk.verdict} risk · ${escapeHtml(assessment.response)}</h3><p>${assessment.eventCount} recent event(s) compared with ${assessment.evidence.baselineSamples} known-good baseline event(s). This is a local rule-based assessment, not a machine-learning prediction.</p>`;
  const factorLabels = [
    ['Behavior / known threat event', assessment.factors.behaviorAnomaly],
    ['Temporal / traffic deviation', assessment.factors.temporalDeviation],
    ['Peer / identity drift', assessment.factors.peerVariance],
    ['Threat intelligence match', assessment.factors.threatIntelligence]
  ];
  insightsList.innerHTML = factorLabels.map(([label, value]) =>
    `<li><strong>${label}:</strong> ${value}/100</li>`
  ).join('');

  const evidence = assessment.evidence;
  const findings = [
    [`${evidence.ruleEvents.length} security-rule event(s)`, evidence.ruleEvents.map(event => event.eventType).join(', ')],
    [`${evidence.novelSourceEvents} unfamiliar source(s)`, 'Not present in the saved baseline'],
    [`${evidence.novelDestinationEvents} unfamiliar destination(s)`, 'Not present in the saved baseline'],
    [`${evidence.novelFingerprintEvents} TLS fingerprint change(s)`, 'Not present in the saved baseline'],
    [`${evidence.unfamiliarHours} event(s) in a new UTC hour`, 'Compared with the baseline hour profile'],
    [`${evidence.trafficSpikes} traffic spike(s)`, 'At least 3× the baseline median request rate']
  ];
  document.getElementById('evidenceBox').innerHTML = `<h3>Observed evidence</h3>${findings
    .map(([title, detail]) => `<div><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></div>`)
    .join('')}`;
  renderChart(assessment.factors);
}

function renderChart(factors) {
  const values = [
    factors.behaviorAnomaly,
    factors.temporalDeviation,
    factors.peerVariance,
    factors.threatIntelligence
  ];
  const width = 260;
  const height = 120;
  const padding = 12;
  const points = values.map((value, index) => {
    const x = padding + index * ((width - padding * 2) / (values.length - 1));
    const y = height - padding - (value / 100) * (height - padding * 2);
    return `${x},${y}`;
  }).join(' ');

  riskChart.innerHTML = `<defs><linearGradient id="areaFill" x1="0" x2="0" y1="0" y2="1">
    <stop offset="0%" stop-color="#76d5ff" stop-opacity="0.8"/><stop offset="100%" stop-color="#76d5ff" stop-opacity="0.05"/>
    </linearGradient></defs><polyline fill="none" stroke="#76d5ff" stroke-width="3" points="${points}"/>
    <polygon points="${points} ${width - padding},${height - padding} ${padding},${height - padding}" fill="url(#areaFill)" opacity="0.7"/>
    <text x="12" y="18" fill="#9db0c8" font-size="10">Behavior · time · peer · threat</text>`;
}

function renderEvents(events, total) {
  document.getElementById('kpiEvents').textContent = total;
  document.getElementById('eventCount').textContent = `${total} retained events`;
  const sources = new Set(events.map(event => event.sourceIp).filter(Boolean));
  document.getElementById('kpiSources').textContent = sources.size;
  const feed = document.getElementById('telemetryFeed');
  feed.innerHTML = events.length ? events.map(event => `<div>
    <strong>${escapeHtml(event.workload)} · ${escapeHtml(event.eventType.replaceAll('_', ' '))}</strong>
    <span>${escapeHtml(new Date(event.timestamp).toLocaleString())} · ${escapeHtml(event.sourceIp || 'source not supplied')} → ${escapeHtml(event.destination || 'destination not supplied')}</span>
  </div>`).join('') : '<p class="form-note">No observed events yet.</p>';
}

async function refreshDashboard(preferredId = selectedEntityId) {
  const [loadedEntities, telemetry, auditVerification, audit] = await Promise.all([
    api('/api/entities'),
    api('/api/telemetry?limit=50'),
    api('/api/audit/verify'),
    api('/api/audit?limit=8')
  ]);
  entities = loadedEntities;
  if (!entities.some(entity => entity.id === preferredId)) preferredId = entities[0]?.id || null;
  selectedEntityId = preferredId;
  renderEntities();
  renderSelected();
  renderEvents(telemetry.events, telemetry.total);

  const auditStatus = document.getElementById('auditStatus');
  auditStatus.textContent = auditVerification.valid
    ? `Hash chain verified · ${auditVerification.checked} entries`
    : `Integrity issue · entry ${auditVerification.checked}`;
  auditStatus.dataset.valid = String(auditVerification.valid);
  document.getElementById('auditFeed').innerHTML = audit.events.length
    ? audit.events.map(event => `<div><strong>${escapeHtml(event.type.replaceAll('_', ' '))}</strong>
      <span>${escapeHtml(new Date(event.timestamp).toLocaleString())} · ${escapeHtml(event.details?.eventCount ?? event.details?.workloads?.length ?? '')} record(s)</span></div>`).join('')
    : '<p class="form-note">No audit activity yet.</p>';
}

function sampleEvents(mode) {
  const now = Date.now();
  const workload = 'orders-api-demo';
  if (mode === 'baseline') {
    return Array.from({ length: 10 }, (_value, index) => ({
      workload,
      type: 'API Gateway',
      timestamp: new Date(now - (10 - index) * 60_000).toISOString(),
      eventType: 'connection',
      sourceIp: '192.0.2.10',
      destination: 'orders-api',
      tlsFingerprint: 'sha256:demo-baseline',
      requestsPerMinute: 20
    }));
  }
  return [
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
  ];
}

function configureExampleDownloads() {
  const baselineUrl = URL.createObjectURL(new Blob([
    JSON.stringify({ events: sampleEvents('baseline') }, null, 2)
  ], { type: 'application/json' }));
  const observationsUrl = URL.createObjectURL(new Blob([
    JSON.stringify({ events: sampleEvents('observations') }, null, 2)
  ], { type: 'application/json' }));
  objectUrls = [baselineUrl, observationsUrl];

  const links = document.getElementById('downloadExamples');
  links.innerHTML = `<a href="${baselineUrl}" download="ncba-baseline-example.json">Download known-good baseline example</a>
    <a href="${observationsUrl}" download="ncba-observation-example.json">Download incident observation example</a>`;
}

async function importFile() {
  const file = document.getElementById('telemetryFile').files[0];
  if (!file) {
    showMessage('Choose a telemetry JSON file first, or run the local incident drill.', true);
    return;
  }
  if (file.size > 1024 * 1024) {
    showMessage('The selected file is larger than the 1 MB local import limit.', true);
    return;
  }
  const button = document.getElementById('importBtn');
  button.disabled = true;
  try {
    const payload = JSON.parse(await file.text());
    const baselineMode = document.getElementById('importMode').value === 'baseline';
    if (
      baselineMode &&
      Array.isArray(payload.events) &&
      payload.events.some(event => typeof event?.workload === 'string' &&
        entities.some(entity =>
          entity.name.toLocaleLowerCase('en-US') === event.workload.trim().toLocaleLowerCase('en-US')
        )) &&
      !window.confirm('This import replaces the selected workload baseline. Have you verified that all included events represent normal, legitimate traffic?')
    ) {
      showMessage('Baseline replacement cancelled.');
      return;
    }
    const result = baselineMode
      ? await api('/api/telemetry/baselines', { method: 'POST', body: JSON.stringify(payload) })
      : await api('/api/telemetry/ingest', { method: 'POST', body: JSON.stringify(payload) });
    if (result.baselines) {
      const summary = result.baselines.map(item => `${item.workload}: ${item.sampleCount} samples`).join('; ');
      showMessage(`Baseline captured. Verify it represents clean traffic before monitoring. ${summary}`);
      const first = entities.find(entity => entity.name.toLocaleLowerCase('en-US') === result.baselines[0]?.workload.toLocaleLowerCase('en-US'));
      await refreshDashboard(first?.id);
    } else {
      const summary = result.assessments.map(item => `${item.workload}: ${item.score}/100 (${item.verdict}; ${item.response})`).join('; ');
      showMessage(`Analysed ${result.storedEvents} event(s). ${summary}`);
      const first = entities.find(entity => entity.name === result.assessments[0]?.workload);
      await refreshDashboard(first?.id);
    }
  } catch (error) {
    showMessage(`Import failed: ${error instanceof SyntaxError ? 'The file is not valid JSON.' : error.message}`, true);
  } finally {
    button.disabled = false;
  }
}

async function runDrill() {
  const button = document.getElementById('sampleBtn');
  button.disabled = true;
  try {
    const result = await api('/api/telemetry/demo', { method: 'POST', body: '{}' });
    await refreshDashboard(entities.find(entity => entity.name === result.workload)?.id);
    showMessage(`SYNTHETIC TRAINING SCENARIO — not a live threat. ${result.workload}: ${result.assessment.score}/100 ${result.assessment.verdict}; recommended response: ${result.assessment.response}.`);
  } catch (error) {
    showMessage(`Local drill failed: ${error.message}`, true);
  } finally {
    button.disabled = false;
  }
}

async function clearLocalData() {
  if (!window.confirm('Delete all imported telemetry and captured workload baselines from this computer? The audit trail is retained.')) {
    return;
  }
  try {
    await api('/api/telemetry', { method: 'DELETE' });
    await refreshDashboard(null);
    showMessage('Local telemetry and baselines cleared. Audit history retained.');
  } catch (error) {
    showMessage(`Could not clear local data: ${error.message}`, true);
  }
}

document.getElementById('importBtn').addEventListener('click', importFile);
document.getElementById('sampleBtn').addEventListener('click', runDrill);
document.getElementById('clearDataBtn').addEventListener('click', clearLocalData);
window.addEventListener('beforeunload', () => objectUrls.forEach(URL.revokeObjectURL));
configureExampleDownloads();

refreshDashboard().catch(error => {
  verdictBox.innerHTML = `<h3>Dashboard unavailable</h3><p>${escapeHtml(error.message)}</p>`;
  showMessage('Start the NCBA server and reload this page.', true);
});
