const config = require('../../config/env');
const { createLogger } = require('../../utils/logger');

const logger = createLogger('api-error');

/**
 * Express error middleware that logs full error context and returns a safe JSON response.
 * @param {Error & { status?: number, statusCode?: number, details?: object }} err - Error object.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 * @param {Function} next - Express next callback.
 * @returns {void}
 */
function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    next(err);
    return;
  }

  const statusCode = Number(err.statusCode || err.status || 500);
  const safeStatus = statusCode >= 400 && statusCode <= 599 ? statusCode : 500;
  const requestId = req.requestId || 'unknown';
  const message = safeStatus >= 500 ? 'Internal server error' : err.message;

  logger.error('request failed', {
    requestId,
    method: req.method,
    path: req.originalUrl || req.url,
    statusCode: safeStatus,
    error: err.message,
    stack: err.stack,
    details: err.details || null
  });

  const response = {
    error: message,
    requestId,
    timestamp: new Date().toISOString()
  };

  if (config.nodeEnv !== 'production') {
    response.debug = {
      originalMessage: err.message,
      stack: err.stack,
      details: err.details || null
    };
  }

  res.status(safeStatus).json(response);
}

module.exports = errorHandler;