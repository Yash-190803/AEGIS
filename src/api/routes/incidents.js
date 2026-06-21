const express = require('express');
const SharedMemory = require('../../core/SharedMemory');
const MessageBus = require('../../core/MessageBus');
const { EVENTS } = require('../../constants/events');
const { generateId } = require('../../utils/idGenerator');
const responseExecutor = require('../../tools/responseExecutorTool');

const router = express.Router();
const memory = SharedMemory.getInstance();
const bus = MessageBus.getInstance();

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function parseLimit(value, fallback = 50) {
  const parsed = parseInt(value || fallback, 10);
  return Number.isNaN(parsed) ? fallback : Math.max(1, Math.min(parsed, 500));
}

function filterIncidents(incidents, query) {
  return incidents
    .filter((incident) => !query.status || incident.status === query.status)
    .filter((incident) => !query.severity || incident.severity === query.severity)
    .slice(0, parseLimit(query.limit));
}

function timelineForIncident(incident) {
  if (incident.forensicsReport && Array.isArray(incident.forensicsReport.attackTimeline)) {
    return incident.forensicsReport.attackTimeline;
  }
  const auditTimeline = memory.auditTrail
    .filter((entry) => entry.incidentId === incident.id || (entry.data && entry.data.incidentId === incident.id))
    .map((entry) => ({
      timestamp: entry.timestamp || entry.loggedAt,
      event: entry.eventType || entry.event || entry.type || 'AUDIT_EVENT',
      evidence: entry.reasoning || JSON.stringify(entry.data || {}),
      affectedSystem: incident.target.hostname,
      mitreTechnique: null
    }));
  return incident.rawEvidence.map((line, index) => ({
    timestamp: new Date(new Date(incident.createdAt).getTime() + index).toISOString(),
    event: 'Raw evidence captured',
    evidence: line,
    affectedSystem: incident.target.hostname,
    mitreTechnique: incident.mitreTechniques[index] || null
  })).concat(auditTimeline).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

function emitRollbackRequested(incident, actionId, reason, requestedBy) {
  return bus.emit(EVENTS.TASK_ROUTED, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'IncidentsRoute',
    eventType: EVENTS.TASK_ROUTED,
    incidentId: incident.id,
    confidence: 1,
    data: {
      targetAgent: 'ResponseAgent',
      task: 'ROLLBACK_RESPONSE',
      incidentId: incident.id,
      actionId,
      reason,
      requestedBy
    },
    reasoning: `Rollback requested by ${requestedBy}.`
  });
}

/**
 * Creates the incidents API router.
 * @returns {object} Express router.
 */
function createIncidentsRouter() {
  router.get('/', (req, res, next) => {
    try {
      const incidents = filterIncidents(memory.getActiveIncidents(), req.query);
      res.json(incidents);
    } catch (error) {
      next(error);
    }
  });

  router.get('/:id', (req, res, next) => {
    try {
      const incident = memory.getIncident(req.params.id);
      if (!incident) throw httpError(404, `Incident not found: ${req.params.id}`);
      res.json(incident);
    } catch (error) {
      next(error);
    }
  });

  router.get('/:id/timeline', (req, res, next) => {
    try {
      const incident = memory.getIncident(req.params.id);
      if (!incident) throw httpError(404, `Incident not found: ${req.params.id}`);
      res.json(timelineForIncident(incident));
    } catch (error) {
      next(error);
    }
  });

  router.post('/:id/rollback/:actionId', async (req, res, next) => {
    try {
      const incident = memory.getIncident(req.params.id);
      if (!incident) throw httpError(404, `Incident not found: ${req.params.id}`);
      const reason = typeof req.body.reason === 'string' && req.body.reason.trim() ? req.body.reason.trim() : 'Analyst requested rollback';
      const requestedBy = typeof req.body.requestedBy === 'string' && req.body.requestedBy.trim() ? req.body.requestedBy.trim() : 'unknown-analyst';
      const action = incident.responses.find((item) => item.actionId === req.params.actionId);
      if (!action) throw httpError(404, `Action not found: ${req.params.actionId}`);
      if (!action.rollbackAvailable) throw httpError(409, `Action ${req.params.actionId} is not rollback-capable.`);
      emitRollbackRequested(incident, req.params.actionId, reason, requestedBy);
      const result = await responseExecutor.rollback_action({
        actionId: req.params.actionId,
        rollbackToken: action.rollbackToken,
        reason
      }, { memory, bus, agentName: 'IncidentsRoute' });
      res.json({ requested: true, requestedBy, result });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

module.exports = createIncidentsRouter;