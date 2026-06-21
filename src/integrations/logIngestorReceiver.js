const config = require('../config/env');
const MessageBus = require('../core/MessageBus');
const SharedMemory = require('../core/SharedMemory');
const { EVENTS } = require('../constants/events');
const { generateId } = require('../utils/idGenerator');
const { createLogger } = require('../utils/logger');

const logger = createLogger('log-ingestor-receiver');
const bus = MessageBus.getInstance();
const memory = SharedMemory.getInstance();
const VALID_LOG_TYPES = Object.freeze(['AUTH', 'NETWORK', 'SYSTEM', 'APPLICATION', 'FIREWALL']);
const MAX_BATCH_LINES = 1000;

const receiverStats = {
  status: 'idle',
  totalBatchesReceived: 0,
  totalLinesReceived: 0,
  rejectedBatches: 0,
  lastBatchAt: null,
  lastBatchId: null,
  lastSource: null,
  lastError: null,
  sources: new Map()
};

/**
 * Builds an HTTP-style error object with a status code for route handlers.
 * @param {number} statusCode - HTTP status code.
 * @param {string} message - Error message.
 * @returns {Error} Error with statusCode attached.
 */
function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

/**
 * Validates the shared internal API key from an Express request.
 * @param {object} req - Express request object.
 * @returns {true} True when the key is valid.
 * @throws {Error} If the key is missing or invalid.
 */
function validateInternalApiKey(req) {
  const key = req && typeof req.get === 'function' ? req.get('X-Internal-Api-Key') : null;
  if (!key || key !== config.internalApiKey) {
    throw httpError(401, 'Invalid or missing X-Internal-Api-Key header.');
  }
  return true;
}

/**
 * Normalizes a single log line from the Go ingestor payload.
 * @param {object} line - Raw line object.
 * @param {number} index - Zero-based line index.
 * @returns {{timestamp: string, filePath: string|null, logType: string, lineNumber: number, content: string}} Normalized line.
 * @throws {Error} If the line does not match the ingestion contract.
 */
function normalizeLine(line, index) {
  if (!line || typeof line !== 'object' || Array.isArray(line)) {
    throw httpError(400, `lines[${index}] must be an object.`);
  }
  if (typeof line.content !== 'string' || line.content.trim().length === 0) {
    throw httpError(400, `lines[${index}].content must be a non-empty string.`);
  }
  if (typeof line.timestamp !== 'string' || Number.isNaN(Date.parse(line.timestamp))) {
    throw httpError(400, `lines[${index}].timestamp must be an ISO8601 string.`);
  }
  const logType = String(line.logType || '').toUpperCase();
  if (!VALID_LOG_TYPES.includes(logType)) {
    throw httpError(400, `lines[${index}].logType must be one of: ${VALID_LOG_TYPES.join(', ')}.`);
  }
  return {
    timestamp: new Date(line.timestamp).toISOString(),
    filePath: typeof line.filePath === 'string' && line.filePath.trim() ? line.filePath.trim() : null,
    logType,
    lineNumber: Number.isInteger(line.lineNumber) && line.lineNumber > 0 ? line.lineNumber : index + 1,
    content: line.content
  };
}

/**
 * Validates and normalizes a raw Go ingestor batch payload.
 * @param {object} body - Raw request body.
 * @returns {{batchId: string, source: string, timestamp: string, logType: string, lines: Array}} Normalized batch.
 * @throws {Error} If the payload is invalid.
 */
function validateLogBatch(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw httpError(400, 'Request body must be an object.');
  }
  if (typeof body.batchId !== 'string' || body.batchId.trim().length === 0) {
    throw httpError(400, 'batchId must be a non-empty string.');
  }
  if (typeof body.source !== 'string' || body.source.trim().length === 0) {
    throw httpError(400, 'source must be a non-empty string.');
  }
  if (!Array.isArray(body.lines) || body.lines.length === 0 || body.lines.length > MAX_BATCH_LINES) {
    throw httpError(400, `lines must be an array with 1-${MAX_BATCH_LINES} items.`);
  }
  const timestamp = typeof body.timestamp === 'string' && !Number.isNaN(Date.parse(body.timestamp))
    ? new Date(body.timestamp).toISOString()
    : new Date().toISOString();
  const lines = body.lines.map(normalizeLine);
  return {
    batchId: body.batchId.trim(),
    source: body.source.trim(),
    timestamp,
    logType: dominantLogType(lines),
    lines
  };
}

/**
 * Determines the dominant log type in a normalized batch.
 * @param {Array<{logType: string}>} lines - Normalized lines.
 * @returns {string} Dominant log type.
 */
function dominantLogType(lines) {
  const counts = lines.reduce((accumulator, line) => {
    accumulator[line.logType] = (accumulator[line.logType] || 0) + 1;
    return accumulator;
  }, {});
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
}

/**
 * Updates receiver health and source statistics after a successful batch.
 * @param {object} batch - Normalized batch.
 * @returns {object} Updated source status.
 */
function recordSuccessfulBatch(batch) {
  const now = new Date().toISOString();
  const sourceStatus = receiverStats.sources.get(batch.source) || {
    source: batch.source,
    batches: 0,
    lines: 0,
    firstSeenAt: now,
    lastSeenAt: null
  };
  sourceStatus.batches += 1;
  sourceStatus.lines += batch.lines.length;
  sourceStatus.lastSeenAt = now;
  receiverStats.sources.set(batch.source, sourceStatus);
  receiverStats.status = 'receiving';
  receiverStats.totalBatchesReceived += 1;
  receiverStats.totalLinesReceived += batch.lines.length;
  receiverStats.lastBatchAt = now;
  receiverStats.lastBatchId = batch.batchId;
  receiverStats.lastSource = batch.source;
  receiverStats.lastError = null;
  return sourceStatus;
}

/**
 * Records a rejected batch for health reporting.
 * @param {Error} error - Validation or delivery error.
 * @returns {void}
 */
function recordRejectedBatch(error) {
  receiverStats.status = 'error';
  receiverStats.rejectedBatches += 1;
  receiverStats.lastError = error.message;
}

/**
 * Emits a normalized batch to the MessageBus using AgentMessageSchema.
 * @param {object} batch - Normalized batch.
 * @returns {boolean} True when MessageBus accepted the event.
 */
function emitLogBatch(batch) {
  memory.addToAuditTrail({
    type: 'LOG_INGESTOR_BATCH_PRE',
    batchId: batch.batchId,
    source: batch.source,
    lineCount: batch.lines.length,
    logType: batch.logType
  });
  const accepted = bus.emit(EVENTS.LOG_BATCH_RECEIVED, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'LogIngestorReceiver',
    eventType: EVENTS.LOG_BATCH_RECEIVED,
    incidentId: null,
    confidence: 1,
    data: batch,
    reasoning: `Received ${batch.lines.length} ${batch.logType} log line(s) from ${batch.source}.`
  });
  memory.addToAuditTrail({
    type: 'LOG_INGESTOR_BATCH_POST',
    batchId: batch.batchId,
    accepted,
    lineCount: batch.lines.length
  });
  return accepted;
}

/**
 * Validates, records, and emits a raw Go ingestor batch.
 * @param {object} body - Raw request body from the Go ingestor.
 * @returns {{accepted: boolean, batch: object, received: number, processedAt: string}} Receipt details.
 * @throws {Error} If validation fails or MessageBus rejects the event.
 */
function receiveLogBatch(body) {
  try {
    const batch = validateLogBatch(body);
    const sourceStatus = recordSuccessfulBatch(batch);
    const accepted = emitLogBatch(batch);
    if (!accepted) {
      throw httpError(500, `MessageBus rejected log batch ${batch.batchId}.`);
    }
    logger.info('Log batch received', {
      batchId: batch.batchId,
      source: batch.source,
      lines: batch.lines.length,
      sourceBatches: sourceStatus.batches
    });
    return { accepted, batch, received: batch.lines.length, processedAt: new Date().toISOString() };
  } catch (error) {
    recordRejectedBatch(error);
    logger.warn('Log batch rejected', { error: error.message, statusCode: error.statusCode || 500 });
    throw error;
  }
}

/**
 * Creates an Express handler for POST /api/internal/log-batch.
 * @returns {Function} Express middleware handler.
 */
function createLogBatchHandler() {
  return (req, res, next) => {
    try {
      validateInternalApiKey(req);
      const receipt = receiveLogBatch(req.body);
      res.status(202).json({
        received: receipt.received,
        batchId: receipt.batch.batchId,
        processedAt: receipt.processedAt
      });
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Returns current receiver health and source statistics.
 * @returns {{status: string, totalBatchesReceived: number, totalLinesReceived: number, rejectedBatches: number, lastBatchAt: string|null, lastBatchId: string|null, lastSource: string|null, lastError: string|null, sources: Array}} Receiver status.
 */
function getIngestorStatus() {
  return {
    status: receiverStats.status,
    totalBatchesReceived: receiverStats.totalBatchesReceived,
    totalLinesReceived: receiverStats.totalLinesReceived,
    rejectedBatches: receiverStats.rejectedBatches,
    lastBatchAt: receiverStats.lastBatchAt,
    lastBatchId: receiverStats.lastBatchId,
    lastSource: receiverStats.lastSource,
    lastError: receiverStats.lastError,
    sources: [...receiverStats.sources.values()]
  };
}

module.exports = {
  createLogBatchHandler,
  emitLogBatch,
  getIngestorStatus,
  receiveLogBatch,
  validateInternalApiKey,
  validateLogBatch
};