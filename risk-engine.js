const WEIGHTS = Object.freeze({
  behaviorAnomaly: 0.4,
  temporalDeviation: 0.3,
  peerVariance: 0.2,
  threatIntelligence: 0.1
});

function getRiskAssessment(entity) {
  const score = Math.round(
    entity.behaviorAnomaly * WEIGHTS.behaviorAnomaly +
    entity.temporalDeviation * WEIGHTS.temporalDeviation +
    entity.peerVariance * WEIGHTS.peerVariance +
    entity.threatIntelligence * WEIGHTS.threatIntelligence
  );

  if (score >= 85) {
    return { score, verdict: 'Critical Risk', response: 'Block', action: 'Revoke certificate and block network traffic' };
  }
  if (score >= 60) {
    return { score, verdict: 'High Risk', response: 'Throttle', action: 'Throttle traffic and increase observation' };
  }
  if (score >= 30) {
    return { score, verdict: 'Moderate Risk', response: 'Challenge', action: 'Request additional workload verification' };
  }
  return { score, verdict: 'Low Risk', response: 'Allow', action: 'Continue monitoring' };
}

function getCertificateStatus(entity) {
  const lifetimeHours = entity.certificateLifetimeHours;
  const ageHours = entity.certificateAgeHours;
  const remainingHours = Math.max(0, lifetimeHours - ageHours);

  return {
    lifetimeHours,
    ageHours,
    remainingHours: Number(remainingHours.toFixed(2)),
    renewalDue: ageHours / lifetimeHours >= 0.8 - Number.EPSILON,
    renewalAtHours: Number((lifetimeHours * 0.8).toFixed(2))
  };
}

module.exports = { WEIGHTS, getRiskAssessment, getCertificateStatus };
