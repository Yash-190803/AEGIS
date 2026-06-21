const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  analyze_log_batch,
  classify_attack_type,
  calculate_risk_score,
  determine_response_level
} = require('../../src/tools/logAnalyzerTool');

const SCENARIO_PATH = path.resolve(__dirname, '..', '..', 'data', 'scenarios', 'ransomware_lateral.json');

function loadScenario() {
  return JSON.parse(fs.readFileSync(SCENARIO_PATH, 'utf8'));
}

function testScenarioMetadata(scenario) {
  assert.strictEqual(scenario.scenarioId, 'RANSOMWARE_LAT_001');
  assert.strictEqual(scenario.name, 'Ransomware With Lateral Movement');
  assert.strictEqual(scenario.logType, 'SYSTEM');
  assert.deepStrictEqual(scenario.logTypes, ['NETWORK', 'AUTH', 'SYSTEM']);
  assert.strictEqual(scenario.expectedDetection, 'RANSOMWARE');
  assert.strictEqual(scenario.expectedResponseLevel, 4);
  for (const technique of ['T1566', 'T1003', 'T1021', 'T1486', 'T1562']) {
    assert.ok(scenario.expectedMitreTechniques.includes(technique), `expected ${technique}`);
  }
}

function testScenarioLogShape(scenario) {
  assert.ok(Array.isArray(scenario.logs), 'logs must be an array');
  assert.strictEqual(scenario.logs.length, 80);
  assert.ok(scenario.logs.some((line) => /PHISHING email delivered/i.test(line)));
  assert.ok(scenario.logs.some((line) => /LSASS handle requested/i.test(line)));
  assert.ok(scenario.logs.some((line) => /NTLM hash extraction/i.test(line)));
  assert.ok(scenario.logs.some((line) => /vssadmin\.exe delete shadows \/all \/quiet/i.test(line)));
  assert.ok(scenario.logs.some((line) => /backup service termination/i.test(line)));
  assert.strictEqual(scenario.logs.filter((line) => /\.encrypted\b/i.test(line)).length, 35);
  assert.ok(scenario.logs.filter((line) => /(SMB|RDP).*workstation-to-workstation/i.test(line)).length >= 20);
}

function testDeterministicDetections(scenario) {
  const analysis = analyze_log_batch({
    logs: scenario.logs,
    logType: scenario.logType,
    baseline: {
      avgRequestsPerMinute: 35,
      knownGoodIPs: ['10.0.0.10', '10.0.0.11']
    }
  });
  const ransomware = analysis.detectedEvents.find((event) => event.type === 'RANSOMWARE');
  const lateral = analysis.detectedEvents.find((event) => event.type === 'LATERAL_MOVEMENT');
  assert.ok(ransomware, 'RANSOMWARE detection should exist');
  assert.ok(lateral, 'LATERAL_MOVEMENT detection should exist');
  assert.strictEqual(ransomware.targetService, 'endpoint');
  assert.strictEqual(ransomware.suggestedMitreTechnique, 'T1486');
  assert.strictEqual(ransomware.severity, 'CRITICAL');
  assert.ok(ransomware.eventCount >= 35);
  assert.ok(ransomware.confidence >= 0.95);
  assert.strictEqual(lateral.suggestedMitreTechnique, 'T1021');
  assert.strictEqual(lateral.severity, 'HIGH');
  assert.ok(lateral.eventCount >= 20);
  assert.ok(lateral.confidence >= 0.9);
  assert.strictEqual(analysis.recommendsEscalation, true);
  assert.ok(analysis.confidence >= 0.95);
  return { ransomware, lateral };
}

function testClassificationAndHITLResponse(scenario, detection) {
  const classification = classify_attack_type({
    anomalyDescription: 'ransomware encryption with shadow copy deletion and mass .encrypted file renames',
    sourceIP: detection.sourceIP,
    targetService: detection.targetService,
    eventCount: detection.eventCount,
    timeWindowSeconds: detection.timeWindowSeconds
  });
  assert.strictEqual(classification.type, scenario.expectedDetection);
  assert.strictEqual(classification.severity, 'CRITICAL');
  assert.strictEqual(classification.suggestedMitreTechnique, 'T1486');
  assert.ok(classification.mitreTactics.includes('Impact'));

  const containmentRisk = calculate_risk_score({
    threatSeverity: 'HIGH',
    targetCriticality: 'HIGH',
    confidence: detection.confidence,
    hasActiveExploit: false,
    isInsiderThreat: false,
    lateralMovementDetected: true,
    dataExfiltrationInProgress: false
  });
  assert.strictEqual(containmentRisk.riskScore, 9);
  assert.strictEqual(containmentRisk.severity, 'CRITICAL');

  const response = determine_response_level({
    riskScore: containmentRisk.riskScore,
    incidentType: classification.type,
    targetCriticality: 'HIGH',
    confidence: detection.confidence
  });
  assert.strictEqual(response.responseLevel, scenario.expectedResponseLevel);
  assert.strictEqual(response.action, 'ISOLATE_MACHINE');
  assert.strictEqual(response.requiresHITL, true);
}

function testLevelFiveStillRequiresHITL() {
  const response = determine_response_level({
    riskScore: 10,
    incidentType: 'RANSOMWARE',
    targetCriticality: 'CRITICAL',
    confidence: 0.98
  });
  assert.strictEqual(response.responseLevel, 5);
  assert.strictEqual(response.action, 'SHUTDOWN');
  assert.strictEqual(response.requiresHITL, true);
}

/**
 * Runs the ransomware lateral movement scenario regression test.
 * @returns {{passed: number}} Test summary.
 * @throws {Error} If any assertion fails.
 */
function runTests() {
  const scenario = loadScenario();
  testScenarioMetadata(scenario);
  testScenarioLogShape(scenario);
  const { ransomware } = testDeterministicDetections(scenario);
  testClassificationAndHITLResponse(scenario, ransomware);
  testLevelFiveStillRequiresHITL();
  return { passed: 5 };
}

if (require.main === module) {
  try {
    const result = runTests();
    console.log(`ransomware.test.js passed (${result.passed} cases)`);
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

module.exports = runTests;