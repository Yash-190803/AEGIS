const express = require('express');
const fs = require('fs');
const path = require('path');
const SharedMemory = require('../../core/SharedMemory');
const MessageBus = require('../../core/MessageBus');
const { EVENTS } = require('../../constants/events');
const { generateId } = require('../../utils/idGenerator');

const router = express.Router();
const memory = SharedMemory.getInstance();
const bus = MessageBus.getInstance();
const SCENARIO_DIR = path.resolve(process.cwd(), 'data', 'scenarios');
const LOG_DIR = path.resolve(process.cwd(), 'data', 'logs');

const SCENARIO_FILES = Object.freeze({
  BRUTE_FORCE: 'brute_force.json',
  RANSOMWARE_LATERAL: 'ransomware_lateral.json',
  SLOW_EXFILTRATION: 'slow_exfiltration.json'
});

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function loadScenario(name) {
  const scenarioName = String(name || '').toUpperCase();
  const fileName = SCENARIO_FILES[scenarioName];
  if (!fileName) {
    throw httpError(400, `scenario must be one of: ${Object.keys(SCENARIO_FILES).join(', ')}`);
  }
  const filePath = path.join(SCENARIO_DIR, fileName);
  if (!fs.existsSync(filePath)) {
    throw httpError(404, `Scenario file not found: ${fileName}`);
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeScenarioLogs(scenarioName, logs) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  const filePath = path.join(LOG_DIR, `scenario_${scenarioName.toLowerCase()}_${Date.now()}.log`);
  fs.writeFileSync(filePath, `${logs.join('\n')}\n`);
  return filePath;
}

function emitLogBatch(scenarioName, scenario, filePath) {
  const batchId = generateId();
  const lines = scenario.logs.map((content, index) => ({
    timestamp: new Date(Date.now() + index).toISOString(),
    filePath,
    logType: scenario.logType || 'APPLICATION',
    lineNumber: index + 1,
    content
  }));
  bus.emit(EVENTS.LOG_BATCH_RECEIVED, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'ScenariosRoute',
    eventType: EVENTS.LOG_BATCH_RECEIVED,
    incidentId: null,
    confidence: 1,
    data: {
      batchId,
      scenario: scenarioName,
      lines,
      source: 'scenario-api',
      logType: scenario.logType || 'APPLICATION',
      expectedDetection: scenario.expectedDetection,
      expectedResponseLevel: scenario.expectedResponseLevel
    },
    reasoning: `Scenario ${scenarioName} loaded and forwarded to Sentinel.`
  });
  return { batchId, lineCount: lines.length };
}

/**
 * Creates the scenario execution API router.
 * @returns {object} Express router.
 */
function createScenariosRouter() {
  router.post('/run', (req, res, next) => {
    try {
      const scenarioName = String(req.body.scenario || '').toUpperCase();
      const scenario = loadScenario(scenarioName);
      if (!Array.isArray(scenario.logs) || scenario.logs.length === 0) {
        throw httpError(422, `Scenario ${scenarioName} has no logs.`);
      }
      const filePath = writeScenarioLogs(scenarioName, scenario.logs);
      const batch = emitLogBatch(scenarioName, scenario, filePath);
      memory.log('ScenariosRoute', 'SCENARIO_RUN', {
        scenario: scenarioName,
        scenarioId: scenario.scenarioId,
        filePath,
        batchId: batch.batchId,
        lineCount: batch.lineCount
      });
      res.status(202).json({
        accepted: true,
        scenario: scenarioName,
        scenarioId: scenario.scenarioId,
        logFile: filePath,
        batchId: batch.batchId,
        linesWritten: batch.lineCount,
        expectedDetection: scenario.expectedDetection,
        expectedResponseLevel: scenario.expectedResponseLevel
      });
    } catch (error) {
      next(error);
    }
  });

  router.get('/', (req, res, next) => {
    try {
      res.json(Object.keys(SCENARIO_FILES).map((scenario) => ({ scenario, file: SCENARIO_FILES[scenario] })));
    } catch (error) {
      next(error);
    }
  });

  return router;
}

module.exports = createScenariosRouter;