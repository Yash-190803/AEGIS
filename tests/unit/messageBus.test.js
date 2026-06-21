const assert = require('assert');

process.env.OPENAI_API_KEY = process.env.OPENAI_API_KEY || 'sk-test-message-bus';
process.env.MOCK_MODE = process.env.MOCK_MODE || 'true';
process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'error';

const MessageBus = require('../../src/core/MessageBus');
const SharedMemory = require('../../src/core/SharedMemory');
const { EVENTS } = require('../../src/constants/events');

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

function resetBus(bus, memory) {
  bus.removeAllListeners();
  resetMemory(memory);
}

function buildMessage(eventType, overrides = {}) {
  return {
    messageId: `unit-${eventType}-${Date.now()}`,
    timestamp: new Date().toISOString(),
    source: 'MessageBusUnitTest',
    eventType,
    incidentId: null,
    confidence: 0.91,
    data: { marker: eventType },
    reasoning: `Unit test event for ${eventType}.`,
    ...overrides
  };
}

function waitForHandlers() {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function testSingletonAndValidEmit(bus, memory) {
  resetBus(bus, memory);
  assert.strictEqual(MessageBus.getInstance(), bus);

  let received = null;
  bus.subscribe(EVENTS.THREAT_DETECTED, 'UnitSubscriber', (message) => {
    received = message;
  });

  const message = buildMessage(EVENTS.THREAT_DETECTED);
  const accepted = bus.emit(EVENTS.THREAT_DETECTED, message);
  assert.strictEqual(accepted, true);
  assert.strictEqual(received.messageId, message.messageId);
  assert.strictEqual(memory.auditTrail.length, 1);
  assert.strictEqual(memory.auditTrail[0].type, 'BUS_EVENT');
  assert.strictEqual(memory.auditTrail[0].eventType, EVENTS.THREAT_DETECTED);
}

function testInvalidMessageRejected(bus, memory) {
  resetBus(bus, memory);
  let received = false;
  bus.subscribe(EVENTS.LOG_BATCH_RECEIVED, 'UnitSubscriber', () => {
    received = true;
  });

  const accepted = bus.emit(EVENTS.LOG_BATCH_RECEIVED, {
    timestamp: new Date().toISOString(),
    source: 'InvalidUnitMessage',
    eventType: EVENTS.LOG_BATCH_RECEIVED,
    incidentId: null,
    confidence: 1,
    data: {},
    reasoning: 'Missing messageId should be rejected.'
  });
  assert.strictEqual(accepted, false);
  assert.strictEqual(received, false);
  assert.strictEqual(memory.auditTrail.length, 0);
}

function testMismatchedEventTypeRejected(bus, memory) {
  resetBus(bus, memory);
  const message = buildMessage(EVENTS.HITL_REQUIRED, { eventType: EVENTS.HITL_APPROVED });
  const accepted = bus.emit(EVENTS.HITL_REQUIRED, message);
  assert.strictEqual(accepted, false);
  assert.strictEqual(memory.auditTrail.length, 0);
}

function testSubscribeValidation(bus, memory) {
  resetBus(bus, memory);
  assert.throws(
    () => bus.subscribe(EVENTS.SYSTEM_READY, '', () => {}),
    /non-empty agentName/
  );
  assert.throws(
    () => bus.subscribe(EVENTS.SYSTEM_READY, 'UnitSubscriber', null),
    /handler to be a function/
  );
}

function testSubscribeToAll(bus, memory) {
  resetBus(bus, memory);
  const seen = [];
  bus.subscribeToAll('AllEventsUnitSubscriber', (message) => {
    seen.push(message.eventType);
  });

  const accepted = bus.emit(EVENTS.SYSTEM_READY, buildMessage(EVENTS.SYSTEM_READY));
  assert.strictEqual(accepted, true);
  assert.deepStrictEqual(seen, [EVENTS.SYSTEM_READY]);
  assert.strictEqual(memory.auditTrail[0].eventType, EVENTS.SYSTEM_READY);
}

function testHandlerErrorIsolation(bus, memory) {
  resetBus(bus, memory);
  let healthyHandlerCalled = false;
  let agentErrorMessage = null;

  bus.subscribe(EVENTS.AGENT_ERROR, 'AgentErrorObserver', (message) => {
    agentErrorMessage = message;
  });
  bus.subscribe(EVENTS.THREAT_DETECTED, 'BrokenSubscriber', () => {
    throw new Error('simulated handler failure');
  });
  bus.subscribe(EVENTS.THREAT_DETECTED, 'HealthySubscriber', () => {
    healthyHandlerCalled = true;
  });

  const accepted = bus.emit(EVENTS.THREAT_DETECTED, buildMessage(EVENTS.THREAT_DETECTED));
  assert.strictEqual(accepted, true);
  return waitForHandlers().then(() => {
    assert.strictEqual(healthyHandlerCalled, true);
    assert.ok(agentErrorMessage, 'AGENT_ERROR should be emitted');
    assert.strictEqual(agentErrorMessage.eventType, EVENTS.AGENT_ERROR);
    assert.strictEqual(agentErrorMessage.data.agentName, 'BrokenSubscriber');
    assert.strictEqual(agentErrorMessage.data.failedEventType, EVENTS.THREAT_DETECTED);
    assert.match(agentErrorMessage.data.errorMessage, /simulated handler failure/);
    assert.ok(memory.auditTrail.some((entry) => entry.eventType === EVENTS.AGENT_ERROR));
  });
}

function runTests() {
  try {
    const bus = MessageBus.getInstance();
    const memory = SharedMemory.getInstance();
    testSingletonAndValidEmit(bus, memory);
    testInvalidMessageRejected(bus, memory);
    testMismatchedEventTypeRejected(bus, memory);
    testSubscribeValidation(bus, memory);
    testSubscribeToAll(bus, memory);
    return testHandlerErrorIsolation(bus, memory).then(() => {
      resetBus(bus, memory);
      return { passed: 6 };
    });
  } catch (error) {
    return Promise.reject(error);
  }
}

if (require.main === module) {
  runTests()
    .then((result) => {
      console.log(`messageBus.test.js passed (${result.passed} cases)`);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

module.exports = runTests;