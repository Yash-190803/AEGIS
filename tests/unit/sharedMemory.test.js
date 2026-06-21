const assert = require('assert');

process.env.OPENAI_API_KEY = process.env.OPENAI_API_KEY || 'sk-test-shared-memory';
process.env.MOCK_MODE = process.env.MOCK_MODE || 'true';
process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'error';

const SharedMemory = require('../../src/core/SharedMemory');

function resetMemory(memory) {
  memory.incidents.clear();
  memory.incidentHistory.length = 0;
  memory.knownBadIPs.clear();
  memory.knownBadDomains.clear();
  memory.knownBadHashes.clear();
  memory.activeCVEs.clear();
  memory.blockedIPs.clear();
  memory.rateLimitedIPs.clear();
  memory.isolatedMachines.clear();
  memory.activeHoneypots.clear();
  memory.honeypotHits.length = 0;
  memory.attackerProfiles.clear();
  memory.detectionRules.length = 0;
  memory.baselineMetrics.clear();
  memory.globalThreatLevel = 'LOW';
  memory.agentStatus.clear();
  memory.pendingHITL.clear();
  memory.auditTrail.length = 0;
  memory.systemStats = {
    totalIncidentsToday: 0,
    totalBlockedToday: 0,
    totalHITLDecisions: 0,
    avgResponseTimeMs: 0,
    startedAt: new Date().toISOString()
  };
}

function incidentInput(overrides = {}) {
  return {
    type: 'BRUTE_FORCE',
    severity: 'HIGH',
    source: {
      ip: '203.0.113.45',
      port: 52300,
      protocol: 'ssh',
      geoLocation: 'documentation-range',
      hostname: 'attacker-demo'
    },
    target: {
      hostname: 'webserver',
      ip: '10.0.0.20',
      service: 'ssh',
      criticality: 'MEDIUM'
    },
    rawEvidence: ['Failed password for root from 203.0.113.45 port 52300 ssh2'],
    confidence: 0.87,
    riskScore: 7,
    responseLevel: 3,
    mitreTechniques: ['T1110'],
    mitreTactics: ['Credential Access'],
    assignedAgents: ['SentinelAgent'],
    ...overrides
  };
}

function testCreateAndUpdateIncident(memory) {
  resetMemory(memory);
  const incident = memory.createIncident(incidentInput());
  assert.ok(incident.id, 'incident receives an id');
  assert.strictEqual(incident.status, 'DETECTING');
  assert.strictEqual(incident.hitlStatus, 'NOT_REQUIRED');
  assert.strictEqual(memory.systemStats.totalIncidentsToday, 1);
  assert.strictEqual(memory.getIncident(incident.id).source.ip, '203.0.113.45');

  const updated = memory.updateIncident(incident.id, {
    status: 'TRIAGING',
    target: { criticality: 'HIGH' },
    enrichedIntel: { historicalMatches: 3 }
  });
  assert.strictEqual(updated.status, 'TRIAGING');
  assert.strictEqual(updated.target.hostname, 'webserver');
  assert.strictEqual(updated.target.criticality, 'HIGH');
  assert.strictEqual(updated.enrichedIntel.historicalMatches, 3);
  assert.ok(Date.parse(updated.updatedAt) >= Date.parse(incident.createdAt));
}

function testValidationFailures(memory) {
  resetMemory(memory);
  assert.throws(
    () => memory.createIncident(incidentInput({ severity: 'SEVERE' })),
    /severity must be one of/
  );
  const incident = memory.createIncident(incidentInput());
  assert.throws(
    () => memory.updateIncident(incident.id, { status: 'INVESTIGATING' }),
    /status must be one of/
  );
  assert.throws(
    () => memory.updateIncident('missing-id', { status: 'CLOSED' }),
    /Incident not found/
  );
}

function testActiveIncidentOrderingAndArchive(memory) {
  resetMemory(memory);
  const low = memory.createIncident(incidentInput({ type: 'UNKNOWN', severity: 'LOW', riskScore: 2 }));
  const critical = memory.createIncident(incidentInput({ type: 'RANSOMWARE', severity: 'CRITICAL', riskScore: 10 }));
  const medium = memory.createIncident(incidentInput({ type: 'SQL_INJECTION', severity: 'HIGH', riskScore: 6 }));
  memory.updateIncident(low.id, { status: 'CLOSED' });

  const active = memory.getActiveIncidents();
  assert.deepStrictEqual(active.map((incident) => incident.id), [critical.id, medium.id]);

  const archived = memory.archiveIncident(medium.id);
  assert.strictEqual(archived.id, medium.id);
  assert.strictEqual(memory.getIncident(medium.id), null);
  assert.strictEqual(memory.incidentHistory.length, 1);
}

function testHITLLifecycle(memory) {
  resetMemory(memory);
  const incident = memory.createIncident(incidentInput({ riskScore: 9, responseLevel: 4 }));
  const request = memory.addHITLRequest(
    incident.id,
    { action: 'ISOLATE_MACHINE', target: 'webserver' },
    'Response level 4 requires analyst approval.',
    'TriageAgent'
  );
  assert.strictEqual(request.incidentId, incident.id);
  assert.strictEqual(memory.pendingHITL.size, 1);
  assert.strictEqual(memory.getIncident(incident.id).hitlStatus, 'PENDING');
  assert.ok(memory.getPendingHITL()[0].timeRemainingSeconds > 0);

  const resolved = memory.resolveHITL(incident.id, 'APPROVED', 'SOC Analyst');
  assert.strictEqual(memory.pendingHITL.size, 0);
  assert.strictEqual(resolved.hitlStatus, 'APPROVED');
  assert.strictEqual(resolved.hitlApprovedBy, 'SOC Analyst');
  assert.strictEqual(memory.systemStats.totalHITLDecisions, 1);
}

function testAuditTrailAndStatus(memory) {
  resetMemory(memory);
  const first = memory.addToAuditTrail({ event: 'FIRST' });
  const second = memory.log('UnitTestAgent', 'SECOND', { ok: true });
  assert.strictEqual(memory.auditTrail[0].entryId, second.entryId);
  assert.strictEqual(memory.auditTrail[1].entryId, first.entryId);
  assert.ok(memory.auditTrail[0].loggedAt);

  const status = memory.updateAgentStatus('SentinelAgent', 'ANALYZING', 'processing unit test batch');
  assert.strictEqual(status.agentName, 'SentinelAgent');
  assert.strictEqual(memory.agentStatus.get('SentinelAgent').status, 'ANALYZING');
}

function testIndicatorsRulesAndSnapshot(memory) {
  resetMemory(memory);
  const incident = memory.createIncident(incidentInput());
  memory.addKnownBadIP('203.0.113.45', 'unit-test-feed', 'HIGH');
  memory.knownBadDomains.set('example.test', { source: 'unit-test-feed', addedAt: new Date().toISOString(), severity: 'LOW' });
  memory.addDetectionRule({ ruleName: 'brute_force_unit', pattern: 'Failed password', threshold: 10 });
  memory.addDetectionRule({ ruleName: 'brute_force_unit', pattern: 'authentication failure', threshold: 8 });
  memory.blockedIPs.set('203.0.113.45', { blockedAt: new Date().toISOString(), reason: 'unit test' });
  memory.activeHoneypots.set('hp-1', { honeypotId: 'hp-1', assetType: 'FAKE_SSH_SERVER' });

  assert.strictEqual(memory.isKnownBadIP('203.0.113.45'), true);
  assert.strictEqual(memory.detectionRules.length, 1);
  assert.strictEqual(memory.detectionRules[0].threshold, 8);

  const snapshot = memory.getSystemSnapshot();
  assert.strictEqual(snapshot.activeIncidentCount, 1);
  assert.strictEqual(snapshot.blockedIPCount, 1);
  assert.strictEqual(snapshot.activeHoneypotCount, 1);
  assert.strictEqual(snapshot.knownBadIndicatorCount, 2);
  assert.strictEqual(memory.getIncident(incident.id).id, incident.id);
}

async function runTests() {
  const memory = SharedMemory.getInstance();
  testCreateAndUpdateIncident(memory);
  testValidationFailures(memory);
  testActiveIncidentOrderingAndArchive(memory);
  testHITLLifecycle(memory);
  testAuditTrailAndStatus(memory);
  testIndicatorsRulesAndSnapshot(memory);
  resetMemory(memory);
  return { passed: 6 };
}

if (require.main === module) {
  runTests()
    .then((result) => {
      console.log(`sharedMemory.test.js passed (${result.passed} cases)`);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

module.exports = runTests;
