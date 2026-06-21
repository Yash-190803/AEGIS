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
const REPORT_DIR = path.resolve(process.cwd(), 'data', 'reports');

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function parseLimit(value, fallback = 100) {
  const parsed = parseInt(value || fallback, 10);
  return Number.isNaN(parsed) ? fallback : Math.max(1, Math.min(parsed, 1000));
}

function inDateRange(entry, from, to) {
  const time = new Date(entry.loggedAt || entry.timestamp || 0).getTime();
  const fromTime = from ? new Date(from).getTime() : 0;
  const toTime = to ? new Date(to).getTime() : Number.MAX_SAFE_INTEGER;
  return time >= fromTime && time <= toTime;
}

function readReportJson(incidentId, fileName) {
  const filePath = path.join(REPORT_DIR, incidentId, fileName);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function emitReportTask(incidentId) {
  return bus.emit(EVENTS.TASK_ROUTED, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'ReportsRoute',
    eventType: EVENTS.TASK_ROUTED,
    incidentId,
    confidence: 1,
    data: {
      targetAgent: 'AuditAgent',
      task: 'GENERATE_COMPLIANCE_REPORT',
      incidentId
    },
    reasoning: 'Compliance report generation requested by API.'
  });
}

/**
 * Creates the reporting and audit API router.
 * @returns {object} Express router.
 */
function createReportsRouter() {
  router.get('/audit', (req, res, next) => {
    try {
      const limit = parseLimit(req.query.limit);
      const entries = memory.auditTrail
        .filter((entry) => !req.query.incidentId || entry.incidentId === req.query.incidentId || (entry.data && entry.data.incidentId === req.query.incidentId))
        .filter((entry) => inDateRange(entry, req.query.from, req.query.to))
        .slice(0, limit);
      res.json(entries);
    } catch (error) {
      next(error);
    }
  });

  router.get('/:incidentId', (req, res, next) => {
    try {
      const incident = memory.getIncident(req.params.incidentId);
      const report = incident && incident.forensicsReport
        ? incident.forensicsReport
        : readReportJson(req.params.incidentId, 'report.json');
      if (!report) throw httpError(404, `Forensics report not found for incident: ${req.params.incidentId}`);
      res.json(report);
    } catch (error) {
      next(error);
    }
  });

  router.get('/:incidentId/compliance', (req, res, next) => {
    try {
      const report = readReportJson(req.params.incidentId, 'compliance_report.json');
      if (!report) throw httpError(404, `Compliance report not found for incident: ${req.params.incidentId}`);
      res.json(report);
    } catch (error) {
      next(error);
    }
  });

  router.post('/:incidentId/compliance', (req, res, next) => {
    try {
      const incident = memory.getIncident(req.params.incidentId);
      if (!incident) throw httpError(404, `Incident not found: ${req.params.incidentId}`);
      emitReportTask(req.params.incidentId);
      res.status(202).json({
        accepted: true,
        incidentId: req.params.incidentId,
        queuedAt: new Date().toISOString()
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

module.exports = createReportsRouter;