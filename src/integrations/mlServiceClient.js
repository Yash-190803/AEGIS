const config = require('../config/env');
const { createLogger } = require('../utils/logger');

const logger = createLogger('ml-service-client');
const REQUEST_TIMEOUT_MS = 5000;
const HEALTH_CACHE_TTL_MS = 3000;
const VALID_RECOMMENDATIONS = new Set(['ESCALATE_TO_LLM', 'MONITOR', 'DISCARD']);

let mlServiceAvailable = false;
let lastHealthCheckAt = 0;
let lastHealthStatus = {
  status: 'unknown',
  available: false,
  checkedAt: null,
  modelLoaded: false,
  version: null,
  error: 'Health check has not run yet.'
};

/**
 * Creates a safe fallback score result when the ML service is unavailable.
 * @param {string} batchId - Batch identifier.
 * @param {string} reason - Human-readable fallback reason.
 * @returns {{anomalyScore: number, confidence: number, recommendation: string, flaggedLines: Array, fallback: boolean, batchId: string, error: string}}
 */
function fallbackScore(batchId, reason) {
  return {
    batchId,
    anomalyScore: 0.5,
    confidence: 0,
    recommendation: 'ESCALATE_TO_LLM',
    flaggedLines: [],
    fallback: true,
    error: reason
  };
}

/**
 * Builds an AbortController-backed timeout signal for fetch.
 * @param {number} timeoutMs - Timeout in milliseconds.
 * @returns {{signal: AbortSignal, cancel: Function}}
 */
function timeoutSignal(timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return {
    signal: controller.signal,
    cancel: () => clearTimeout(timer)
  };
}

/**
 * Reads a fetch response body as JSON with useful error context.
 * @param {Response} response - Fetch response.
 * @returns {Promise<object>} Parsed response body.
 * @throws {Error} If body parsing fails.
 */
async function readJsonResponse(response) {
  try {
    const text = await response.text();
    if (!text) {
      return {};
    }
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Unable to parse ML service response JSON: ${error.message}`);
  }
}

/**
 * Performs a JSON HTTP request against the ML service.
 * @param {string} path - Endpoint path beginning with slash.
 * @param {object} options - Fetch options.
 * @returns {Promise<object>} Parsed JSON response.
 * @throws {Error} If the request fails or returns a non-2xx status.
 */
async function requestJson(path, options = {}) {
  const timeout = timeoutSignal(REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${config.mlServiceUrl}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      signal: timeout.signal
    });
    const payload = await readJsonResponse(response);
    if (!response.ok) {
      const message = payload.error || payload.message || `HTTP ${response.status}`;
      throw new Error(`ML service ${path} failed: ${message}`);
    }
    return payload;
  } catch (error) {
    const timedOut = error.name === 'AbortError';
    throw new Error(`${timedOut ? 'ML service request timed out' : 'ML service request failed'}: ${error.message}`);
  } finally {
    timeout.cancel();
  }
}

/**
 * Normalizes ML service score responses into SentinelAgent's expected contract.
 * @param {object} payload - Raw ML service response.
 * @param {string} batchId - Original batch identifier.
 * @returns {{anomalyScore: number, confidence: number, recommendation: string, flaggedLines: Array, fallback: boolean}}
 */
function normalizeScoreResponse(payload, batchId) {
  const anomalyScore = Number.isFinite(payload.anomalyScore) ? payload.anomalyScore : 0.5;
  const confidence = Number.isFinite(payload.confidence) ? payload.confidence : 0;
  const recommendation = VALID_RECOMMENDATIONS.has(payload.recommendation) ? payload.recommendation : 'ESCALATE_TO_LLM';
  return {
    ...payload,
    batchId: payload.batchId || batchId,
    anomalyScore: Math.max(0, Math.min(1, anomalyScore)),
    confidence: Math.max(0, Math.min(1, confidence)),
    recommendation,
    flaggedLines: Array.isArray(payload.flaggedLines) ? payload.flaggedLines : [],
    fallback: Boolean(payload.fallback)
  };
}

/**
 * Updates cached availability state from a health payload.
 * @param {object} payload - Health response or synthesized error payload.
 * @returns {object} Cached health status.
 */
function setHealthStatus(payload) {
  const checkedAt = new Date().toISOString();
  mlServiceAvailable = payload.status === 'healthy' && payload.modelLoaded === true;
  lastHealthCheckAt = Date.now();
  lastHealthStatus = {
    status: payload.status || (mlServiceAvailable ? 'healthy' : 'unhealthy'),
    available: mlServiceAvailable,
    checkedAt,
    modelLoaded: Boolean(payload.modelLoaded),
    version: payload.version || null,
    baselineLoaded: Boolean(payload.baselineLoaded),
    uptimeSeconds: payload.uptimeSeconds || 0,
    error: payload.error || payload.startupError || null
  };
  return lastHealthStatus;
}

/**
 * Score a batch of logs for anomalies via the Python ML service.
 * @param {string[]} logs - Raw log lines.
 * @param {string} logType - Log type enum.
 * @param {string} batchId - UUID for tracking.
 * @returns {Promise<{anomalyScore: number, confidence: number, recommendation: string, flaggedLines: Array, fallback: boolean}>}
 */
async function scoreBatch(logs, logType, batchId) {
  try {
    if (!Array.isArray(logs) || logs.length === 0) {
      return fallbackScore(batchId, 'No log lines supplied to ML service client.');
    }
    if (!mlServiceAvailable) {
      await checkMLServiceHealth({ force: true });
    }
    if (!mlServiceAvailable) {
      return fallbackScore(batchId, lastHealthStatus.error || 'ML service is unavailable.');
    }
    const payload = await requestJson('/score', {
      method: 'POST',
      body: JSON.stringify({ logs, logType, batchId })
    });
    return normalizeScoreResponse(payload, batchId);
  } catch (error) {
    mlServiceAvailable = false;
    lastHealthStatus = {
      ...lastHealthStatus,
      status: 'unhealthy',
      available: false,
      checkedAt: new Date().toISOString(),
      error: error.message
    };
    logger.warn('ML service call failed, falling back to LLM-only mode', { batchId, error: error.message });
    return fallbackScore(batchId, error.message);
  }
}

/**
 * Checks ML service health and updates module availability state.
 * @param {{force?: boolean}} options - Cache control options.
 * @returns {Promise<object>} Health status summary.
 */
async function checkMLServiceHealth(options = {}) {
  try {
    if (!options.force && Date.now() - lastHealthCheckAt < HEALTH_CACHE_TTL_MS) {
      return lastHealthStatus;
    }
    const payload = await requestJson('/health', { method: 'GET' });
    const status = setHealthStatus(payload);
    logger.info('ML service health checked', { status });
    return status;
  } catch (error) {
    const status = setHealthStatus({ status: 'unhealthy', modelLoaded: false, error: error.message });
    logger.warn('ML service health check failed', { error: error.message });
    return status;
  }
}

/**
 * Submits feedback examples to retrain the Python anomaly detector.
 * @param {Array<object|number[]>} examples - Labeled or vectorized examples for retraining.
 * @returns {Promise<object>} Retrain result or unavailable status.
 */
async function submitFeedback(examples) {
  try {
    if (!Array.isArray(examples) || examples.length === 0) {
      throw new Error('submitFeedback requires a non-empty examples array.');
    }
    if (!mlServiceAvailable) {
      await checkMLServiceHealth({ force: true });
    }
    if (!mlServiceAvailable) {
      return { accepted: false, fallback: true, error: lastHealthStatus.error || 'ML service is unavailable.' };
    }
    const payload = await requestJson('/retrain', {
      method: 'POST',
      body: JSON.stringify({ examples })
    });
    logger.info('ML feedback submitted', { examples: examples.length, status: payload.status });
    return { accepted: true, fallback: false, ...payload };
  } catch (error) {
    logger.warn('ML feedback submission failed', { error: error.message });
    return { accepted: false, fallback: true, error: error.message };
  }
}

module.exports = {
  scoreBatch,
  checkMLServiceHealth,
  submitFeedback
};