const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  analyze_log_batch,
  classify_attack_type,
  calculate_risk_score,
  determine_response_level
} = require('../../src/tools/logAnalyzerTool');

const SCENARIO_PATH = path.resolve(__dirname, '..', '..', 'data', 'scenarios', 'brute_force.json');

function loadScenario() {
  return JSON.parse(fs.readFileSync(SCENARIO_PATH, 'utf8'));
}

function testScenarioMetadata(scenario) {
  assert.strictEqual(scenario.scenarioId, 'BRUTE_FORCE_001');
  assert.strictEqual(scenario.name, 'SSH Brute Force Attack');
  assert.strictEqual(scenario.logType, 'AUTH');
  assert.strictEqual(scenario.expectedDetection, 'BRUTE_FORCE');
  assert.strictEqual(scenario.expectedResponseLevel, 3);
  assert.deepStrictEqual(scenario.expectedMitreTechniques, ['T1110', 'T1110.001']);
}

function testScenarioLogShape(scenario) {
  assert.ok(Array.isArray(scenario.logs), 'logs must be an array');
  assert.strictEqual(scenario.logs.length, 150);
  assert.strictEqual(scenario.logs.filter((line) => /Failed password/.test(line)).length, 149);
  assert.strictEqual(scenario.logs.filter((line) => /Accepted password/.test(line)).length, 1);
  assert.ok(scenario.logs.every((line) => line.includes('203.0.113.45')));
  assert.ok(scenario.logs[0].includes('port 52300'));
  assert.ok(scenario.logs[147].includes('port 52447'));
  assert.ok(scenario.logs[148].includes('port 52449'));
  assert.ok(scenario.logs[149].includes('Accepted password for backup'));
  assert.ok(scenario.logs[149].includes('port 52450'));
}

function testDeterministicDetection(scenario) {
  const analysis = analyze_log_batch({
    logs: scenario.logs,
    logType: scenario.logType,
    baseline: {
      avgRequestsPerMinute: 12,
      knownGoodIPs: ['10.0.0.10']
    }
  });
  const bruteForce = analysis.detectedEvents.find((event) => event.type === 'BRUTE_FORCE');
  assert.ok(bruteForce, 'BRUTE_FORCE detection should exist');
  assert.strictEqual(bruteForce.sourceIP, '203.0.113.45');
  assert.strictEqual(bruteForce.targetService, 'ssh');
  assert.strictEqual(bruteForce.suggestedMitreTechnique, 'T1110');
  assert.strictEqual(bruteForce.severity, 'HIGH');
  assert.ok(bruteForce.eventCount >= 148);
  assert.ok(bruteForce.confidence >= 0.9);
  assert.strictEqual(analysis.recommendsEscalation, true);
  assert.ok(analysis.confidence >= 0.9);
  return bruteForce;
}

function testClassificationAndResponseMapping(scenario, detection) {
  const classification = classify_attack_type({
    anomalyDescription: `${detection.eventCount} failed SSH password attempts from one source IP`,
    sourceIP: detection.sourceIP,
    targetService: detection.targetService,
    eventCount: detection.eventCount,
    timeWindowSeconds: detection.timeWindowSeconds
  });
  assert.strictEqual(classification.type, scenario.expectedDetection);
  assert.strictEqual(classification.severity, 'HIGH');
  assert.strictEqual(classification.suggestedMitreTechnique, 'T1110');
  assert.ok(classification.mitreTactics.includes('Credential Access'));

  const risk = calculate_risk_score({
    threatSeverity: classification.severity,
    targetCriticality: 'MEDIUM',
    confidence: detection.confidence,
    hasActiveExploit: false,
    isInsiderThreat: false,
    lateralMovementDetected: false,
    dataExfiltrationInProgress: false
  });
  assert.strictEqual(risk.riskScore, 6);
  assert.strictEqual(risk.severity, 'HIGH');

  const response = determine_response_level({
    riskScore: risk.riskScore,
    incidentType: classification.type,
    targetCriticality: 'MEDIUM',
    confidence: detection.confidence
  });
  assert.strictEqual(response.responseLevel, scenario.expectedResponseLevel);
  assert.strictEqual(response.action, 'BLOCK_IP');
  assert.strictEqual(response.requiresHITL, false);
}

/**
 * Runs the brute-force scenario regression test.
 * @returns {{passed: number}} Test summary.
 * @throws {Error} If any assertion fails.
 */
function runTests() {
  const scenario = loadScenario();
  testScenarioMetadata(scenario);
  testScenarioLogShape(scenario);
  const detection = testDeterministicDetection(scenario);
  testClassificationAndResponseMapping(scenario, detection);
  return { passed: 4 };
}

if (require.main === module) {
  try {
    const result = runTests();
    console.log(`brute_force.test.js passed (${result.passed} cases)`);
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

module.exports = runTests;