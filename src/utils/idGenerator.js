const { v4: uuidv4 } = require('uuid');

/**
 * Generates a RFC 4122 version 4 UUID.
 * @returns {string} UUID string.
 */
function generateId() {
  return uuidv4();
}

/**
 * Generates a short display identifier derived from a UUID.
 * @returns {string} First eight characters of a UUID.
 */
function generateShortId() {
  return generateId().slice(0, 8);
}

module.exports = {
  generateId,
  generateShortId
};