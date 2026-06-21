const assert = require('assert');

const {
  combineConfidences,
  adjustForMLAlignment,
  normalizeIsolationForestScore
} = require('../../src/core/ConfidenceEngine');

function assertClose(actual, expected, epsilon = 0.0001) {
  assert.ok(
    Math.abs(actual - expected) <= epsilon,
    `Expected ${actual} to be within ${epsilon} of ${expected}`
  );
}

function testCombineEmptyAndSingle() {
  assert.strictEqual(combineConfidences([]), 0);
  assert.strictEqual(combineConfidences([0.72]), 0.72);
  assert.strictEqual(combineConfidences([1.2]), 1);
  assert.strictEqual(combineConfidences([-0.4]), 0);
}

function testCombineMultipleSignals() {
  assertClose(combineConfidences([0.8, 0.9]), 0.922);
  assertClose(combineConfidences([0.6, 0.7, 0.8]), 0.8014);
  assert.strictEqual(combineConfidences([0.99, 0.99, 0.99]), 0.99);
  assert.ok(combineConfidences([0.2, 0.95]) > 0.5);
}

function testCombineValidation() {
  assert.throws(() => combineConfidences('0.8'), /requires an array/);
  assert.throws(() => combineConfidences([0.5, Number.NaN]), /finite number/);
  assert.throws(() => combineConfidences([0.5, Infinity]), /finite number/);
}

function testAdjustForMLAlignment() {
  assert.strictEqual(adjustForMLAlignment(0.8, null, null), 0.8);
  assertClose(adjustForMLAlignment(0.82, 0.2, 'DISCARD'), 0.62);
  assertClose(adjustForMLAlignment(0.35, 0.1, 'DISCARD'), 0.4);
  assertClose(adjustForMLAlignment(0.72, 0.84, 'ESCALATE_TO_LLM'), 0.82);
  assertClose(adjustForMLAlignment(0.72, 0.55, 'MONITOR'), 0.82);
  assertClose(adjustForMLAlignment(0.96, 0.92, 'ESCALATE_TO_LLM'), 0.99);
  assert.strictEqual(adjustForMLAlignment(0.49, 0.91, 'ESCALATE_TO_LLM'), 0.49);
}

function testAdjustValidation() {
  assert.throws(() => adjustForMLAlignment('0.8', 0.5, 'MONITOR'), /finite number/);
  assert.throws(() => adjustForMLAlignment(0.8, Number.NaN, 'MONITOR'), /finite number/);
}

function testNormalizeIsolationForestScore() {
  assert.strictEqual(normalizeIsolationForestScore(0), 0);
  assert.strictEqual(normalizeIsolationForestScore(-0.25), 0.5);
  assert.strictEqual(normalizeIsolationForestScore(-0.5), 1);
  assert.strictEqual(normalizeIsolationForestScore(-1), 1);
  assert.strictEqual(normalizeIsolationForestScore(0.2), 0);
}

function testNormalizeValidation() {
  assert.throws(() => normalizeIsolationForestScore('bad'), /finite number/);
  assert.throws(() => normalizeIsolationForestScore(Number.NaN), /finite number/);
}

async function runTests() {
  try {
    testCombineEmptyAndSingle();
    testCombineMultipleSignals();
    testCombineValidation();
    testAdjustForMLAlignment();
    testAdjustValidation();
    testNormalizeIsolationForestScore();
    testNormalizeValidation();
    return { passed: 7 };
  } catch (error) {
    throw new Error(`confidenceEngine.test.js failed: ${error.message}`);
  }
}

if (require.main === module) {
  runTests()
    .then((result) => {
      console.log(`confidenceEngine.test.js passed (${result.passed} cases)`);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

module.exports = runTests;
