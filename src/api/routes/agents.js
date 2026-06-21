const express = require('express');
const SharedMemory = require('../../core/SharedMemory');
const MessageBus = require('../../core/MessageBus');
const { EVENTS } = require('../../constants/events');
const { generateId } = require('../../utils/idGenerator');

const router = express.Router();
const memory = SharedMemory.getInstance();
const bus = MessageBus.getInstance();

const REDTEAM_SCENARIOS = Object.freeze(['BRUTE_FORCE', 'SQL_INJECTION', 'LATERAL_MOVEMENT', 'PRIVILEGE_ESCALATION', 'DATA_EXFILTRATION', 'RANSOMWARE']);

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function emitRouteEvent(eventType, data, reasoning) {
  return bus.emit(eventType, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'AgentsRoute',
    eventType,
    incidentId: data.incidentId || null,
    confidence: typeof data.confidence === 'number' ? data.confidence : 1,
    data,
    reasoning
  });
}

function recentIndicators(map, limit = 20) {
  return [...map.entries()]
    .map(([indicator, value]) => ({ indicator, ...value }))
    .sort((a, b) => new Date(b.addedAt || 0).getTime() - new Date(a.addedAt || 0).getTime())
    .slice(0, limit);
}

/**
 * Creates the agents and operational-control API router.
 * @returns {object} Express router.
 */
function createAgentsRouter() {
  router.get('/status', (req, res, next) => {
    try {
      res.json([...memory.agentStatus.values()]);
    } catch (error) {
      next(error);
    }
  });

  router.get('/health', (req, res, next) => {
    try {
      const statuses = [...memory.agentStatus.values()];
      const errorCount = statuses.filter((status) => status.status === 'ERROR').length;
      res.json({
        agentCount: statuses.length,
        errorCount,
        healthy: errorCount === 0,
        statuses
      });
    } catch (error) {
      next(error);
    }
  });

  router.get('/deception/honeypots', (req, res, next) => {
    try {
      const honeypots = [...memory.activeHoneypots.values()].map((honeypot) => ({
        ...honeypot,
        hitCount: memory.honeypotHits.filter((hit) => hit.honeypotId === honeypot.honeypotId).length
      }));
      res.json(honeypots);
    } catch (error) {
      next(error);
    }
  });

  router.get('/intel/indicators', (req, res, next) => {
    try {
      res.json({
        counts: {
          ips: memory.knownBadIPs.size,
          domains: memory.knownBadDomains.size,
          hashes: memory.knownBadHashes.size,
          cves: memory.activeCVEs.size
        },
        recent: {
          ips: recentIndicators(memory.knownBadIPs),
          domains: recentIndicators(memory.knownBadDomains),
          hashes: recentIndicators(memory.knownBadHashes),
          cves: recentIndicators(memory.activeCVEs)
        }
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/redteam/simulate', (req, res, next) => {
    try {
      const scenario = String(req.body.scenario || 'BRUTE_FORCE').toUpperCase();
      if (!REDTEAM_SCENARIOS.includes(scenario)) {
        throw httpError(400, `scenario must be one of: ${REDTEAM_SCENARIOS.join(', ')}`);
      }
      emitRouteEvent(EVENTS.RED_TEAM_SIMULATION_STARTED, {
        scenario,
        requestedBy: req.body.requestedBy || 'api',
        confidence: 1
      }, `Red-team simulation ${scenario} requested by API.`);
      res.status(202).json({ accepted: true, scenario, queuedAt: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

module.exports = createAgentsRouter;