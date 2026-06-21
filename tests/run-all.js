process.env.OPENAI_API_KEY = process.env.OPENAI_API_KEY || 'sk-test-runner';
process.env.MOCK_MODE = process.env.MOCK_MODE || 'true';
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'error';

const path = require('path');

const TESTS = Object.freeze([
  {
    name: 'sharedMemory',
    file: path.join(__dirname, 'unit', 'sharedMemory.test.js')
  },
  {
    name: 'messageBus',
    file: path.join(__dirname, 'unit', 'messageBus.test.js')
  },
  {
    name: 'confidenceEngine',
    file: path.join(__dirname, 'unit', 'confidenceEngine.test.js')
  }
]);

/**
 * Runs a single test module exported as a function.
 * @param {{name: string, file: string}} testCase - Test metadata.
 * @returns {Promise<{name: string, status: string, passed: number, durationMs: number}>} Test result.
 * @throws {Error} If the module cannot be loaded or the test fails.
 */
async function runTestCase(testCase) {
  const started = Date.now();
  try {
    const runner = require(testCase.file);
    if (typeof runner !== 'function') {
      throw new Error(`${testCase.name} did not export a test runner function.`);
    }
    const result = await runner();
    return {
      name: testCase.name,
      status: 'PASS',
      passed: result && Number.isInteger(result.passed) ? result.passed : 1,
      durationMs: Date.now() - started
    };
  } catch (error) {
    error.message = `${testCase.name} failed: ${error.message}`;
    throw error;
  }
}

/**
 * Runs the full Node.js unit test suite.
 * @returns {Promise<{passedSuites: number, failedSuites: number, totalCases: number, results: Array}>} Summary.
 */
async function runAll() {
  const results = [];
  const failures = [];
  for (const testCase of TESTS) {
    try {
      const result = await runTestCase(testCase);
      results.push(result);
      console.log(`[PASS] ${result.name} (${result.passed} cases, ${result.durationMs}ms)`);
    } catch (error) {
      const failure = {
        name: testCase.name,
        status: 'FAIL',
        error: error.message,
        stack: error.stack
      };
      failures.push(failure);
      results.push(failure);
      console.error(`[FAIL] ${testCase.name}: ${error.message}`);
    }
  }

  const totalCases = results.reduce((sum, result) => sum + (result.passed || 0), 0);
  const summary = {
    passedSuites: results.length - failures.length,
    failedSuites: failures.length,
    totalCases,
    results
  };
  console.log(`AEGIS test summary: ${summary.passedSuites}/${TESTS.length} suites passed, ${totalCases} cases passed.`);
  if (failures.length > 0) {
    const error = new Error(`${failures.length} test suite(s) failed.`);
    error.summary = summary;
    throw error;
  }
  return summary;
}

if (require.main === module) {
  runAll()
    .then(() => {
      process.exit(0);
    })
    .catch((error) => {
      console.error(error.message);
      if (error.summary) {
        for (const result of error.summary.results.filter((item) => item.status === 'FAIL')) {
          console.error(result.stack || result.error);
        }
      }
      process.exit(1);
    });
}

module.exports = runAll;