const dotenv = require('dotenv');
const chalk = require('chalk');

dotenv.config();

const DEFAULT_PORT = 3000;
const MIN_PORT = 1024;
const MAX_PORT = 65535;

/**
 * Reads an environment variable with an optional default value.
 * @param {string} key - Environment variable name.
 * @param {string | undefined} defaultValue - Fallback value.
 * @returns {string}
 */
function readEnv(key, defaultValue = undefined) {
  const value = process.env[key];
  if (value === undefined || value === '') {
    if (defaultValue !== undefined) {
      return defaultValue;
    }
    return '';
  }
  return value;
}

/**
 * Parses an integer environment variable.
 * @param {string} key - Environment variable name.
 * @param {string} defaultValue - Fallback string value.
 * @returns {number}
 * @throws {Error} If the resolved value is not a valid integer.
 */
function parseIntegerEnv(key, defaultValue) {
  const rawValue = readEnv(key, defaultValue);
  const parsed = parseInt(rawValue, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${key} must be an integer. Received: ${rawValue}`);
  }
  return parsed;
}

/**
 * Parses a floating-point environment variable.
 * @param {string} key - Environment variable name.
 * @param {string} defaultValue - Fallback string value.
 * @returns {number}
 * @throws {Error} If the resolved value is not a valid number.
 */
function parseFloatEnv(key, defaultValue) {
  const rawValue = readEnv(key, defaultValue);
  const parsed = parseFloat(rawValue);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${key} must be a number. Received: ${rawValue}`);
  }
  return parsed;
}

/**
 * Parses a boolean environment variable.
 * @param {string} key - Environment variable name.
 * @param {string} defaultValue - Fallback string value.
 * @returns {boolean}
 * @throws {Error} If the resolved value is not true or false.
 */
function parseBooleanEnv(key, defaultValue) {
  const rawValue = readEnv(key, defaultValue).trim().toLowerCase();
  if (rawValue === 'true') {
    return true;
  }
  if (rawValue === 'false') {
    return false;
  }
  throw new Error(`Environment variable ${key} must be true or false. Received: ${rawValue}`);
}

const openAiApiKey = readEnv('OPENAI_API_KEY');

if (!openAiApiKey || !openAiApiKey.startsWith('sk-')) {
  console.error(chalk.red('AEGIS startup failed: OPENAI_API_KEY is required and must start with "sk-".'));
  console.error(chalk.red('Create a .env file from .env.example, then set OPENAI_API_KEY=sk-your-real-key.'));
  console.error(chalk.red('Example: copy .env.example .env, edit .env, then run npm start again.'));
  process.exit(1);
}

let port = parseIntegerEnv('PORT', String(DEFAULT_PORT));
if (port < MIN_PORT || port > MAX_PORT) {
  console.warn(chalk.yellow(`Invalid PORT ${port}. PORT must be between ${MIN_PORT} and ${MAX_PORT}; defaulting to ${DEFAULT_PORT}.`));
  port = DEFAULT_PORT;
}

const config = Object.freeze({
  openAiApiKey,
  port,
  nodeEnv: readEnv('NODE_ENV', 'development'),
  mockMode: parseBooleanEnv('MOCK_MODE', 'false'),
  logLevel: readEnv('LOG_LEVEL', 'info'),
  hitlTimeoutSeconds: parseIntegerEnv('HITL_TIMEOUT_SECONDS', '300'),
  maxIncidentsInMemory: parseIntegerEnv('MAX_INCIDENTS_IN_MEMORY', '500'),
  riskAutoRespondThreshold: parseIntegerEnv('RISK_AUTO_RESPOND_THRESHOLD', '3'),
  confidenceAutoRespondThreshold: parseFloatEnv('CONFIDENCE_AUTO_RESPOND_THRESHOLD', '0.75'),
  openaiModelPrimary: readEnv('OPENAI_MODEL_PRIMARY', 'gpt-4o'),
  openaiModelFast: readEnv('OPENAI_MODEL_FAST', 'gpt-4o-mini'),
  maxOpenAIRetries: parseIntegerEnv('MAX_OPENAI_RETRIES', '3'),
  openaiRetryBaseDelayMs: parseIntegerEnv('OPENAI_RETRY_BASE_DELAY_MS', '1000'),
  mlServiceUrl: readEnv('ML_SERVICE_URL', 'http://localhost:5001'),
  mlServicePort: parseIntegerEnv('ML_SERVICE_PORT', '5001'),
  internalApiKey: readEnv('INTERNAL_API_KEY', 'aegis-internal-key-dev'),
  logIngestorWatchDir: readEnv('LOG_INGESTOR_WATCH_DIR', './data/logs')
});

module.exports = config;