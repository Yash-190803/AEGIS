const express = require('express');
const SharedMemory = require('../../core/SharedMemory');
const MessageBus = require('../../core/MessageBus');
const { EVENTS } = require('../../constants/events');
const { generateId } = require('../../utils/idGenerator');

const router = express.Router();
const memory = SharedMemory.getInstance();
const bus = MessageBus.getInstance();
const NAME_PATTERN = /^[a-zA-Z0-9 ]{2,80}$/;

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function validateHumanName(value, fieldName) {
  if (typeof value !== 'string' || !NAME_PATTERN.test(value.trim())) {
    throw httpError(400, `${fieldName} must be 2-80 characters and contain only letters, numbers, and spaces.`);
  }
  return value.trim();
}

function emitHITL(eventType, incidentId, data, actor) {
  return bus.emit(eventType, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'HITLRoute',
    eventType,
    incidentId,
    confidence: 1,
    data,
    reasoning: `${eventType} recorded by ${actor}.`
  });
}

/**
 * Creates the human-in-the-loop API router.
 * @returns {object} Express router.
 */
function createHITLRouter() {
  router.get('/pending', (req, res, next) => {
    try {
      res.json(memory.getPendingHITL());
    } catch (error) {
      next(error);
    }
  });

  router.post('/:incidentId/approve', (req, res, next) => {
    try {
      const approvedBy = validateHumanName(req.body.approvedBy, 'approvedBy');
      const incident = memory.getIncident(req.params.incidentId);
      if (!incident) throw httpError(404, `Incident not found: ${req.params.incidentId}`);
      const updatedIncident = memory.pendingHITL.has(incident.id)
        ? memory.resolveHITL(incident.id, 'APPROVED', approvedBy)
        : memory.updateIncident(incident.id, { hitlStatus: 'APPROVED', hitlApprovedBy: approvedBy, hitlTimestamp: new Date().toISOString() });
      emitHITL(EVENTS.HITL_APPROVED, incident.id, {
        incidentId: incident.id,
        approvedBy,
        notes: req.body.notes || '',
        updatedStatus: updatedIncident.hitlStatus
      }, approvedBy);
      res.json({ approved: true, incident: updatedIncident });
    } catch (error) {
      next(error);
    }
  });

  router.post('/:incidentId/reject', (req, res, next) => {
    try {
      const rejectedBy = validateHumanName(req.body.rejectedBy, 'rejectedBy');
      const reason = typeof req.body.reason === 'string' && req.body.reason.trim() ? req.body.reason.trim() : 'Rejected by analyst';
      const incident = memory.getIncident(req.params.incidentId);
      if (!incident) throw httpError(404, `Incident not found: ${req.params.incidentId}`);
      const updatedIncident = memory.pendingHITL.has(incident.id)
        ? memory.resolveHITL(incident.id, 'REJECTED', rejectedBy)
        : memory.updateIncident(incident.id, { hitlStatus: 'REJECTED', hitlApprovedBy: null, hitlTimestamp: new Date().toISOString() });
      memory.updateIncident(incident.id, { status: 'ESCALATED' });
      emitHITL(EVENTS.HITL_REJECTED, incident.id, {
        incidentId: incident.id,
        rejectedBy,
        reason,
        updatedStatus: updatedIncident.hitlStatus
      }, rejectedBy);
      res.json({ rejected: true, incident: memory.getIncident(incident.id) });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

module.exports = createHITLRouter;