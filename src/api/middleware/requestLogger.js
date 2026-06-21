const { createLogger } = require('../../utils/logger');
const { generateShortId } = require('../../utils/idGenerator');

const logger = createLogger('api-request');

function sanitizeHeaders(headers) {
  const sanitized = { ...headers };
  for (const key of Object.keys(sanitized)) {
    if (/authorization|api-key|cookie|token/i.test(key)) {
      sanitized[key] = '[REDACTED]';
    }
  }
  return sanitized;
}

/**
 * Express middleware that records structured request and response metadata.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 * @param {Function} next - Express next callback.
 * @returns {void}
 */
function requestLogger(req, res, next) {
  const requestId = generateShortId();
  const startedAt = Date.now();
  req.requestId = requestId;

  logger.info('request started', {
    requestId,
    method: req.method,
    path: req.originalUrl || req.url,
    ip: req.ip,
    userAgent: req.get ? req.get('user-agent') : undefined,
    headers: sanitizeHeaders(req.headers || {})
  });

  res.on('finish', () => {
    const durationMs = Date.now() - startedAt;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    logger[level]('request completed', {
      requestId,
      method: req.method,
      path: req.originalUrl || req.url,
      statusCode: res.statusCode,
      durationMs,
      contentLength: res.getHeader ? res.getHeader('content-length') : undefined
    });
  });

  next();
}

module.exports = requestLogger;