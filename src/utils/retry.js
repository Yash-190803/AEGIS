/**
 * Sleeps for a specified duration.
 * @param {number} delayMs - Number of milliseconds to wait.
 * @returns {Promise<void>} Promise that resolves after the delay.
 */
function sleep(delayMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

/**
 * Determines whether an error represents an OpenAI rate-limit response.
 * @param {Error & { status?: number, code?: string, error?: { code?: string } }} error - Error to inspect.
 * @returns {boolean} True when the error is a rate-limit condition.
 */
function isOpenAIRateLimitError(error) {
  return Boolean(
    error
      && (
        error.status === 429
        || error.code === 'rate_limit_exceeded'
        || (error.error && error.error.code === 'rate_limit_exceeded')
      )
  );
}

/**
 * Wraps an async operation in exponential retry logic with jitter.
 * @param {Function} fn - Async or sync function to execute.
 * @param {object} options - Retry configuration.
 * @param {number} [options.maxRetries=3] - Number of retries after the initial attempt.
 * @param {number} [options.baseDelayMs=1000] - Base delay in milliseconds.
 * @param {number} [options.maxDelayMs=10000] - Maximum delay in milliseconds.
 * @param {Function | null} [options.onRetry=null] - Optional callback invoked before each retry.
 * @returns {Promise<*>} Result returned by fn.
 * @throws {Error} If fn is not callable, retry settings are invalid, or all attempts fail.
 */
async function withRetry(fn, options = {}) {
  const {
    maxRetries = 3,
    baseDelayMs = 1000,
    maxDelayMs = 10000,
    onRetry = null
  } = options;

  if (typeof fn !== 'function') {
    throw new Error('withRetry requires fn to be a function.');
  }
  if (!Number.isInteger(maxRetries) || maxRetries < 0) {
    throw new Error(`withRetry maxRetries must be a non-negative integer. Received: ${maxRetries}`);
  }
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0) {
    throw new Error(`withRetry baseDelayMs must be a non-negative number. Received: ${baseDelayMs}`);
  }
  if (!Number.isFinite(maxDelayMs) || maxDelayMs < 0) {
    throw new Error(`withRetry maxDelayMs must be a non-negative number. Received: ${maxDelayMs}`);
  }
  if (onRetry !== null && typeof onRetry !== 'function') {
    throw new Error('withRetry onRetry must be a function when provided.');
  }

  let lastError = null;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      if (attempt >= maxRetries) {
        const originalMessage = error && error.message ? error.message : String(error);
        const wrappedError = new Error(`All ${maxRetries} retries failed: ${originalMessage}`);
        wrappedError.cause = error;
        throw wrappedError;
      }

      const retryNumber = attempt + 1;
      const jitterMs = Math.floor(Math.random() * 101);
      const rateLimitMultiplier = isOpenAIRateLimitError(error) ? 2 : 1;
      const exponentialDelayMs = baseDelayMs * (2 ** attempt);
      const delayMs = Math.min((exponentialDelayMs * rateLimitMultiplier) + jitterMs, maxDelayMs);

      if (onRetry) {
        try {
          await onRetry(error, retryNumber);
        } catch (callbackError) {
          const callbackMessage = callbackError && callbackError.message ? callbackError.message : String(callbackError);
          const wrappedCallbackError = new Error(`Retry callback failed before retry ${retryNumber}: ${callbackMessage}`);
          wrappedCallbackError.cause = callbackError;
          throw wrappedCallbackError;
        }
      }

      await sleep(delayMs);
    }
  }

  const fallbackMessage = lastError && lastError.message ? lastError.message : String(lastError);
  const fallbackError = new Error(`All ${maxRetries} retries failed: ${fallbackMessage}`);
  fallbackError.cause = lastError;
  throw fallbackError;
}

module.exports = {
  withRetry,
  isOpenAIRateLimitError
};