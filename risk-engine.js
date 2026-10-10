const WEIGHTS = Object.freeze({
  behaviorAnomaly: 0.4,
  temporalDeviation: 0.3,
  peerVariance: 0.2,
  threatIntelligence: 0.1
});

function getRiskAssessment(signals) {
  const score = Math.round(
    signals.behaviorAnomaly * WEIGHTS.behaviorAnomaly +
    signals.temporalDeviation * WEIGHTS.temporalDeviation +
    signals.peerVariance * WEIGHTS.peerVariance +
    signals.threatIntelligence * WEIGHTS.threatIntelligence
  );

  if (score >= 85) {
    return { score, verdict: 'Critical Risk', response: 'Containment review' };
  }
  if (score >= 60) {
    return { score, verdict: 'High Risk', response: 'Throttle / investigate' };
  }
  if (score >= 30) {
    return { score, verdict: 'Moderate Risk', response: 'Step-up verification' };
  }
  return { score, verdict: 'Low Risk', response: 'Allow and monitor' };
}

module.exports = { WEIGHTS, getRiskAssessment };
