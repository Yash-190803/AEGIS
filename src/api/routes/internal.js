const express = require('express');
const config = require('../../config/env');
const MessageBus = require('../../core/MessageBus');
const { EVENTS } = require('../../constants/events');
const { generateId } = require('../../utils/idGenerator');

const router = express.Router();
const bus = MessageBus.getInstance();
const VALID_LOG_TYPES = Object.freeze(['AUTH', 'NETWORK', 'SYSTEM', 'APPLICATION', 'FIREWALL']);

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function validateInternalKey(req) {
  const key = req.get('X-Internal-Api-Key');
  if (!key || key !== config.internalApiKey) {
    throw httpError(401, 'Invalid or missing X-Internal-Api-Key header.');
  }
}

function validateLine(line, index) {
  if (!line || typeof line !== 'object') {
    throw httpError(400, `lines[${index}] must be an object.`);
  }
  if (typeof line.content !== 'string' || line.content.length === 0) {
    throw httpError(400, `lines[${index}].content must be a non-empty string.`);
  }
  if (typeof line.timestamp !== 'string' || Number.isNaN(Date.parse(line.timestamp))) {
    throw httpError(400, `lines[${index}].timestamp must be an ISO8601 string.`);
  }
  if (typeof line.logType !== 'string' || !VALID_LOG_TYPES.includes(line.logType)) {
    throw httpError(400, `lines[${index}].logType must be one of: ${VALID_LOG_TYPES.join(', ')}`);
  }
  return {
    timestamp: line.timestamp,
    filePath: typeof line.filePath === 'string' ? line.filePath : null,
    logType: line.logType,
    lineNumber: Number.isInteger(line.lineNumber) ? line.lineNumber : index + 1,
    content: line.content
  };
}

function validateBatch(body) {
  if (!body || typeof body !== 'object') {
    throw httpError(400, 'Request body must be an object.');
  }
  if (typeof body.batchId !== 'string' || body.batchId.trim().length === 0) {
    throw httpError(400, 'batchId must be a non-empty string.');
  }
  if (!Array.isArray(body.lines) || body.lines.length === 0 || body.lines.length > 1000) {
    throw httpError(400, 'lines must be an array with 1-1000 items.');
  }
  if (typeof body.source !== 'string' || body.source.trim().length === 0) {
    throw httpError(400, 'source must be a non-empty string.');
  }
  return {
    batchId: body.batchId.trim(),
    source: body.source.trim(),
    timestamp: typeof body.timestamp === 'string' ? body.timestamp : new Date().toISOString(),
    lines: body.lines.map(validateLine)
  };
}

function emitBatch(batch) {
  bus.emit(EVENTS.LOG_BATCH_RECEIVED, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'InternalLogBatchRoute',
    eventType: EVENTS.LOG_BATCH_RECEIVED,
    incidentId: null,
    confidence: 1,
    data: batch,
    reasoning: `Received ${batch.lines.length} log line(s) from ${batch.source}.`
  });
}

/**
 * Creates the internal service API router.
 * @returns {object} Express router.
 */
function createInternalRouter() {
  router.post('/log-batch', (req, res, next) => {
    try {
      validateInternalKey(req);
      const batch = validateBatch(req.body);
      emitBatch(batch);
      res.status(202).json({
        received: batch.lines.length,
        batchId: batch.batchId,
        processedAt: new Date().toISOString()
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

module.exports = createInternalRouter;