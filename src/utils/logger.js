const fs = require('fs');
const path = require('path');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const config = require('../config/env');

const levels = { error: 0, warn: 1, info: 2, agent: 3, threat: 4, audit: 5 };
const colors = { error: 'red', warn: 'yellow', info: 'white', agent: 'cyan', threat: 'red bold', audit: 'yellow' };
const logDirectory = path.resolve(process.cwd(), 'logs');

winston.addColors(colors);

if (!fs.existsSync(logDirectory)) {
  fs.mkdirSync(logDirectory, { recursive: true });
}

const structuredFormat = winston.format.printf((info) => {
  const service = info.service || 'aegis';
  const metadata = info.metadata && Object.keys(info.metadata).length > 0
    ? ` ${JSON.stringify(info.metadata)}`
    : '';
  return `[${info.timestamp}] [${info.level}] [${service}] ${info.message}${metadata}`;
});

const fileFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.metadata({ fillExcept: ['timestamp', 'level', 'message', 'service'] }),
  structuredFormat
);

const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.metadata({ fillExcept: ['timestamp', 'level', 'message', 'service'] }),
  structuredFormat
);

const baseLogger = winston.createLogger({
  levels,
  level: config.logLevel,
  exitOnError: false,
  transports: [
    new winston.transports.Console({
      level: config.logLevel,
      format: consoleFormat,
      handleExceptions: true,
      handleRejections: true
    }),
    new DailyRotateFile({
      level: config.logLevel,
      filename: path.join(logDirectory, 'aegis-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: false,
      maxFiles: '14d',
      format: fileFormat,
      handleExceptions: true,
      handleRejections: true
    })
  ]
});

/**
 * Creates a service-scoped Winston logger tagged with the given service name.
 * @param {string} service - Logical service, module, or agent name to include in each log line.
 * @returns {winston.Logger} Winston logger child instance with custom AEGIS levels.
 * @throws {Error} If service is not a non-empty string.
 */
function createLogger(service) {
  if (typeof service !== 'string' || service.trim().length === 0) {
    throw new Error('createLogger requires a non-empty service name.');
  }
  return baseLogger.child({ service: service.trim() });
}

const logger = createLogger('aegis');

module.exports = {
  createLogger,
  logger
};