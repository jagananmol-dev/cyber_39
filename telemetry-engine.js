const { getRiskAssessment } = require('./risk-engine');

const EVENT_SEVERITY = Object.freeze({
  connection: 0,
  authentication_failure: 55,
  rate_anomaly: 75,
  unexpected_egress: 85,
  certificate_expired: 95,
  certificate_mismatch: 95,
  token_replay: 100,
  threat_intelligence_match: 100
});

function workloadKey(name) {
  return `workload:${name.trim().toLocaleLowerCase('en-US')}`;
}

function uniqueValues(events, field) {
  return [...new Set(events.map(event => event[field]).filter(Boolean))];
}

function median(values) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

function captureBaseline(workload, events) {
  return {
    workload,
    sampleCount: events.length,
    capturedAt: new Date().toISOString(),
    sourceIps: uniqueValues(events, 'sourceIp'),
    destinations: uniqueValues(events, 'destination'),
    tlsFingerprints: uniqueValues(events, 'tlsFingerprint'),
    utcHours: uniqueValues(events, 'timestamp').map(timestamp => new Date(timestamp).getUTCHours()),
    medianRequestsPerMinute: median(events.map(event => event.requestsPerMinute))
  };
}

function percentage(numerator, denominator) {
  return denominator === 0 ? 0 : Math.round((numerator / denominator) * 100);
}

function analyzeTelemetry(events, baseline) {
  const total = events.length;
  const novelSourceEvents = events.filter(event =>
    event.sourceIp && !baseline.sourceIps.includes(event.sourceIp)
  ).length;
  const novelDestinationEvents = events.filter(event =>
    event.destination && !baseline.destinations.includes(event.destination)
  ).length;
  const novelFingerprintEvents = events.filter(event =>
    event.tlsFingerprint && !baseline.tlsFingerprints.includes(event.tlsFingerprint)
  ).length;
  const unfamiliarHours = events.filter(event =>
    !baseline.utcHours.includes(new Date(event.timestamp).getUTCHours())
  ).length;
  const ruleEvents = events.filter(event => event.eventType !== 'connection');
  const behaviorAnomaly = Math.max(
    ...ruleEvents.map(event => EVENT_SEVERITY[event.eventType]),
    0
  );
  const trafficSpikes = baseline.medianRequestsPerMinute > 0
    ? events.filter(event => event.requestsPerMinute >= baseline.medianRequestsPerMinute * 3).length
    : 0;
  const sourceNovelty = percentage(novelSourceEvents, total);
  const destinationNovelty = percentage(novelDestinationEvents, total);
  const fingerprintDrift = percentage(novelFingerprintEvents, total);
  const peerVariance = Math.round((sourceNovelty + destinationNovelty + fingerprintDrift) / 3);
  const temporalDeviation = Math.max(
    percentage(unfamiliarHours, total),
    percentage(trafficSpikes, total)
  );
  const threatIntelligence = events.some(event => event.eventType === 'threat_intelligence_match') ? 100 : 0;

  const assessment = getRiskAssessment({
    behaviorAnomaly,
    temporalDeviation,
    peerVariance,
    threatIntelligence
  });
  const confidence = baseline.sampleCount >= 20 && total >= 10
    ? 'High'
    : baseline.sampleCount >= 10 && total >= 3
      ? 'Moderate'
      : 'Low';

  return {
    ...assessment,
    confidence,
    eventCount: total,
    factors: {
      behaviorAnomaly,
      temporalDeviation,
      peerVariance,
      threatIntelligence
    },
    evidence: {
      ruleEvents: ruleEvents.map(event => ({
        eventType: event.eventType,
        timestamp: event.timestamp,
        sourceIp: event.sourceIp || null,
        destination: event.destination || null
      })),
      novelSourceEvents,
      novelDestinationEvents,
      novelFingerprintEvents,
      unfamiliarHours,
      trafficSpikes,
      baselineSamples: baseline.sampleCount
    }
  };
}

module.exports = { EVENT_SEVERITY, analyzeTelemetry, captureBaseline, workloadKey };
