const entityList = document.getElementById('entityList');
const riskScoreEl = document.getElementById('riskScore');
const riskRing = document.getElementById('riskRing');
const verdictBox = document.getElementById('verdictBox');
const insightsList = document.getElementById('insightsList');
const riskChart = document.getElementById('riskChart');
const liveThreatFeed = document.getElementById('liveThreatFeed');
const certificateStatus = document.getElementById('certificateStatus');
const entityStatus = document.getElementById('entityStatus');
const auditStatus = document.getElementById('auditStatus');

const formMap = {
  name: document.getElementById('entityName'),
  type: document.getElementById('entityType'),
  lifetime: document.getElementById('certificateLifetime'),
  agent: document.getElementById('agentInstalled'),
  behaviorAnomaly: document.getElementById('behaviorAnomaly'),
  temporalDeviation: document.getElementById('temporalDeviation'),
  peerVariance: document.getElementById('peerVariance'),
  threatIntelligence: document.getElementById('threatIntelligence')
};

const rangeLabels = {
  behaviorAnomaly: document.getElementById('behaviorAnomalyValue'),
  temporalDeviation: document.getElementById('temporalDeviationValue'),
  peerVariance: document.getElementById('peerVarianceValue'),
  threatIntelligence: document.getElementById('threatIntelligenceValue')
};

let entities = [];
let selectedEntityId = null;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers }
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error?.message || `Request failed (${response.status}).`);
  }
  return data;
}

function formPayload() {
  return {
    id: selectedEntityId,
    name: formMap.name.value.trim(),
    type: formMap.type.value,
    certificateLifetimeHours: Number(formMap.lifetime.value),
    certificateAgeHours: Number(document.getElementById('certificateAge').value),
    agentInstalled: formMap.agent.value === 'true',
    behaviorAnomaly: Number(formMap.behaviorAnomaly.value),
    temporalDeviation: Number(formMap.temporalDeviation.value),
    peerVariance: Number(formMap.peerVariance.value),
    threatIntelligence: Number(formMap.threatIntelligence.value)
  };
}

function getPreviewScore(payload = formPayload()) {
  return Math.round(
    payload.behaviorAnomaly * 0.4 +
    payload.temporalDeviation * 0.3 +
    payload.peerVariance * 0.2 +
    payload.threatIntelligence * 0.1
  );
}

function getRisk(score) {
  if (score >= 85) return { verdict: 'Critical Risk', response: 'Block', color: '#ff6679' };
  if (score >= 60) return { verdict: 'High Risk', response: 'Throttle', color: '#ff8a65' };
  if (score >= 30) return { verdict: 'Moderate Risk', response: 'Challenge', color: '#f7bf5d' };
  return { verdict: 'Low Risk', response: 'Allow', color: '#6ee7a8' };
}

function renderRiskChart(score, payload = formPayload()) {
  const values = [
    payload.behaviorAnomaly,
    payload.temporalDeviation,
    payload.peerVariance,
    payload.threatIntelligence
  ];
  const width = 260;
  const height = 120;
  const padding = 12;
  const points = values.map((value, index) => {
    const x = padding + index * ((width - padding * 2) / (values.length - 1));
    const y = height - padding - (value / 100) * (height - padding * 2);
    return `${x},${y}`;
  }).join(' ');

  riskChart.innerHTML = `
    <defs><linearGradient id="areaFill" x1="0" x2="0" y1="0" y2="1">
      <stop offset="0%" stop-color="#76d5ff" stop-opacity="0.8"/>
      <stop offset="100%" stop-color="#76d5ff" stop-opacity="0.05"/>
    </linearGradient></defs>
    <polyline fill="none" stroke="#76d5ff" stroke-width="3" points="${points}" />
    <polygon points="${points} ${width - padding},${height - padding} ${padding},${height - padding}" fill="url(#areaFill)" opacity="0.7" />
    <text x="12" y="18" fill="#9db0c8" font-size="10">Weighted risk factors</text>
    <text x="200" y="18" fill="#9db0c8" font-size="10">${score}/100</text>
  `;
}

function renderAssessment(score, payload = formPayload(), entity = null) {
  const risk = getRisk(score);
  const certificateAge = payload.certificateAgeHours;
  const renewalDue = certificateAge / payload.certificateLifetimeHours >= 0.8 - Number.EPSILON;
  const remaining = Math.max(0, payload.certificateLifetimeHours - certificateAge);

  riskScoreEl.textContent = score;
  riskRing.style.setProperty('--ring-score', score);
  riskRing.style.background = `conic-gradient(${risk.color} ${score}%, rgba(255,255,255,0.04) 0)`;
  verdictBox.innerHTML = `<h3>${risk.verdict}</h3><p>Policy response: ${risk.response}. ${escapeHtml(risk.response === 'Block'
    ? 'Critical signals require immediate review and approved containment.'
    : risk.response === 'Throttle'
      ? 'Elevated signals call for throttling and closer observation.'
      : risk.response === 'Challenge'
        ? 'Request additional workload verification before allowing normal access.'
        : 'No elevated behavior signal was found in this demonstration assessment.')}</p>`;
  certificateStatus.textContent = renewalDue
    ? `Renewal due · ${remaining.toFixed(1)} h remaining`
    : `Active · ${remaining.toFixed(1)} h remaining`;

  const factors = [
    ['Behavior anomaly', payload.behaviorAnomaly],
    ['Temporal deviation', payload.temporalDeviation],
    ['Peer-group variance', payload.peerVariance],
    ['Threat intelligence', payload.threatIntelligence]
  ];
  insightsList.innerHTML = factors.map(([label, value]) =>
    `<li><strong>${label}:</strong> ${value}/100</li>`
  ).join('') + `<li><strong>Recommended response:</strong> ${risk.response}</li>`;
  entityStatus.textContent = entity
    ? `Identity state: ${entity.status.toUpperCase()} · ${entity.agentInstalled ? 'Runtime agent enabled' : 'Network-only observation'}`
    : 'Unsaved risk preview';
  renderRiskChart(score, payload);
}

function renderEntities() {
  entityList.innerHTML = entities.map(entity => {
    const risk = getRisk(entity.score);
    const riskType = entity.score >= 85 ? 'critical' : entity.score >= 60 ? 'high' : entity.score >= 30 ? 'medium' : 'low';
    return `
      <button class="entity-card ${entity.id === selectedEntityId ? 'active' : ''}" data-risk="${riskType}" data-id="${escapeHtml(entity.id)}" type="button">
        <span class="entity-top">
          <span class="entity-name">${escapeHtml(entity.name)}</span>
          <span class="entity-chip">${risk.verdict}</span>
        </span>
        <span class="entity-meta">
          <span>${escapeHtml(entity.type)} · ${escapeHtml(entity.status)}</span>
          <span>Risk ${entity.score}</span>
        </span>
      </button>`;
  }).join('');

  entityList.querySelectorAll('.entity-card').forEach(card => {
    card.addEventListener('click', () => selectEntity(card.dataset.id));
  });

  const highRisk = entities.filter(entity => entity.score >= 60).length;
  const contained = entities.filter(entity => ['revoked', 'isolated'].includes(entity.status)).length;
  const averageRisk = entities.length
    ? Math.round(entities.reduce((sum, entity) => sum + entity.score, 0) / entities.length)
    : 0;
  document.getElementById('kpiEntities').textContent = entities.length;
  document.getElementById('kpiHighRisk').textContent = highRisk;
  document.getElementById('kpiRevoked').textContent = contained;
  document.getElementById('kpiRisk').textContent = averageRisk;
}

function selectEntity(id) {
  const entity = entities.find(item => item.id === id);
  if (!entity) return;
  selectedEntityId = entity.id;
  formMap.name.value = entity.name;
  formMap.type.value = entity.type;
  formMap.lifetime.value = entity.certificateLifetimeHours;
  document.getElementById('certificateAge').value = entity.certificateAgeHours;
  formMap.agent.value = String(entity.agentInstalled);
  Object.keys(rangeLabels).forEach(key => {
    formMap[key].value = entity[key];
    rangeLabels[key].textContent = entity[key];
  });
  renderEntities();
  renderAssessment(entity.score, formPayload(), entity);
}

async function refreshEntities() {
  entities = await api('/api/entities');
  if (!entities.some(entity => entity.id === selectedEntityId)) {
    selectedEntityId = entities[0]?.id || null;
  }
  renderEntities();
  if (selectedEntityId) selectEntity(selectedEntityId);
}

async function runAnalysis() {
  const button = document.getElementById('runAnalysisBtn');
  button.disabled = true;
  try {
    const result = await api('/api/analyze', {
      method: 'POST',
      body: JSON.stringify(formPayload())
    });
    await refreshEntities();
    renderAssessment(result.score, formPayload(), result);
    await refreshAudit();
  } catch (error) {
    verdictBox.innerHTML = `<h3>Analysis failed</h3><p>${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
  }
}

async function addEntity() {
  const entity = {
    name: `New workload ${entities.length + 1}`,
    type: 'API Gateway',
    certificateLifetimeHours: 24,
    certificateAgeHours: 0,
    agentInstalled: true,
    behaviorAnomaly: 10,
    temporalDeviation: 10,
    peerVariance: 10,
    threatIntelligence: 0
  };
  try {
    const created = await api('/api/entities', { method: 'POST', body: JSON.stringify(entity) });
    selectedEntityId = created.id;
    await refreshEntities();
    await refreshAudit();
  } catch (error) {
    verdictBox.innerHTML = `<h3>Could not add identity</h3><p>${escapeHtml(error.message)}</p>`;
  }
}

async function applyAction(action) {
  if (!selectedEntityId) return;
  const payload = { action };
  if (action !== 'renew') {
    payload.approvers = [
      document.getElementById('approverOne').value.trim(),
      document.getElementById('approverTwo').value.trim()
    ];
  }

  try {
    const result = await api(`/api/entities/${encodeURIComponent(selectedEntityId)}/actions`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    verdictBox.innerHTML = `<h3>${escapeHtml(result.entity.status.toUpperCase())}</h3><p>${escapeHtml(result.message)}</p>`;
    await refreshEntities();
    await refreshAudit();
  } catch (error) {
    verdictBox.innerHTML = `<h3>Action not applied</h3><p>${escapeHtml(error.message)}</p>`;
  }
}

async function refreshAudit() {
  try {
    const [result, verification] = await Promise.all([
      api('/api/audit?limit=8'),
      api('/api/audit/verify')
    ]);
    auditStatus.textContent = verification.valid
      ? `Verified · ${verification.checked} events`
      : `Integrity issue · event ${verification.checked}`;
    auditStatus.dataset.valid = String(verification.valid);
    liveThreatFeed.innerHTML = result.events.length
      ? result.events.map(event => `
          <div>
            <strong>${escapeHtml(event.type.replaceAll('_', ' '))}</strong>
            <span>${escapeHtml(new Date(event.timestamp).toLocaleString())} · ${escapeHtml(event.entityId)}</span>
          </div>`).join('')
      : '<p class="form-note">No events recorded yet.</p>';
  } catch (error) {
    auditStatus.textContent = `Unavailable: ${error.message}`;
    auditStatus.dataset.valid = 'false';
  }
}

function previewAnalysis() {
  Object.entries(rangeLabels).forEach(([key, label]) => {
    label.textContent = formMap[key].value;
  });
  const payload = formPayload();
  renderAssessment(getPreviewScore(payload), payload, null);
}

Object.values(formMap).forEach(input => {
  input.addEventListener('input', () => {
    const ageInput = document.getElementById('certificateAge');
    ageInput.max = formMap.lifetime.value;
    if (Number(ageInput.value) > Number(formMap.lifetime.value)) {
      ageInput.value = formMap.lifetime.value;
    }
    previewAnalysis();
  });
  input.addEventListener('change', previewAnalysis);
});
document.getElementById('certificateAge').addEventListener('input', previewAnalysis);
document.getElementById('analysisForm').addEventListener('submit', event => {
  event.preventDefault();
  runAnalysis();
});
document.getElementById('runAnalysisBtn').addEventListener('click', runAnalysis);
document.getElementById('addEntityBtn').addEventListener('click', addEntity);
document.getElementById('revokeBtn').addEventListener('click', () => applyAction('revoke'));
document.getElementById('quarantineBtn').addEventListener('click', () => applyAction('isolate'));
document.getElementById('restoreBtn').addEventListener('click', () => applyAction('restore'));
document.getElementById('renewBtn').addEventListener('click', () => applyAction('renew'));

refreshEntities()
  .then(refreshAudit)
  .catch(error => {
    verdictBox.innerHTML = `<h3>Dashboard unavailable</h3><p>${escapeHtml(error.message)}</p>`;
  });
