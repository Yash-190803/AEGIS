const INCIDENT_TYPES = Object.freeze(['BRUTE_FORCE', 'SQL_INJECTION', 'LATERAL_MOVEMENT', 'PRIVILEGE_ESCALATION', 'DATA_EXFILTRATION', 'RANSOMWARE', 'PHISHING', 'ZERO_DAY', 'UNKNOWN']);
const SEVERITIES = Object.freeze(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const INCIDENT_STATUSES = Object.freeze(['DETECTING', 'ENRICHING', 'TRIAGING', 'RESPONDING', 'CONTAINED', 'ESCALATED', 'CLOSED', 'FALSE_POSITIVE']);
const CRITICALITIES = Object.freeze(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const RESPONSE_ACTIONS = Object.freeze(['ALERT_ONLY', 'RATE_LIMIT', 'BLOCK_IP', 'ISOLATE_MACHINE', 'SHUTDOWN']);
const RESPONSE_STATUSES = Object.freeze(['PENDING', 'EXECUTED', 'ROLLED_BACK', 'FAILED']);
const HITL_STATUSES = Object.freeze(['NOT_REQUIRED', 'PENDING', 'APPROVED', 'REJECTED', 'TIMEOUT']);
const ML_RECOMMENDATIONS = Object.freeze(['ESCALATE_TO_LLM', 'MONITOR', 'DISCARD']);

const INCIDENT_CREATE_REQUIRED_FIELDS = Object.freeze(['type', 'severity', 'source', 'target', 'rawEvidence', 'confidence']);
const AGENT_MESSAGE_REQUIRED_FIELDS = Object.freeze(['messageId', 'timestamp', 'source', 'eventType', 'incidentId', 'confidence', 'data', 'reasoning']);

const INCIDENT_SCHEMA = Object.freeze({
  id: 'uuid-v4',
  createdAt: 'ISO8601',
  updatedAt: 'ISO8601',
  type: INCIDENT_TYPES,
  severity: SEVERITIES,
  status: INCIDENT_STATUSES,
  source: 'Incident source object',
  target: 'Incident target object',
  rawEvidence: 'string[]',
  confidence: 'number 0.0-1.0',
  riskScore: 'integer 1-10',
  responseLevel: 'integer 1-5',
  mitreTechniques: 'string[]',
  mitreTactics: 'string[]',
  enrichedIntel: 'Threat intelligence object',
  responses: 'Response action objects[]',
  forensicsReport: 'null | ForensicsReportSchema',
  requiresHITL: 'boolean',
  hitlStatus: HITL_STATUSES,
  hitlApprovedBy: 'string | null',
  hitlTimestamp: 'ISO8601 | null',
  assignedAgents: 'string[]',
  agentNotes: 'Agent note objects[]',
  mlPreScore: 'number 0.0-1.0 | null',
  mlRecommendation: 'ESCALATE_TO_LLM | MONITOR | DISCARD | null'
});

const AGENT_MESSAGE_SCHEMA = Object.freeze({
  messageId: 'uuid-v4',
  timestamp: 'ISO8601',
  source: 'AgentName string',
  eventType: 'EVENT_TYPE_CONSTANT',
  incidentId: 'uuid | null',
  confidence: 'number 0.0-1.0',
  data: 'object',
  reasoning: 'string'
});

const FORENSICS_REPORT_SCHEMA = Object.freeze({
  reportId: 'uuid',
  incidentId: 'uuid',
  generatedAt: 'ISO8601',
  executiveSummary: 'string',
  attackTimeline: 'Timeline entry objects[]',
  affectedSystems: 'string[]',
  indicatorsOfCompromise: 'string[]',
  attackerTTPs: 'string[]',
  businessImpactAssessment: 'string',
  containmentActions: 'string[]',
  recommendations: 'string[]',
  rawEvidenceBundle: 'string[]',
  confidenceInAttribution: 'number 0.0-1.0'
});

/**
 * Checks whether a value is a plain object.
 * @param {*} value - Value to inspect.
 * @returns {boolean} True when the value is a non-array object.
 */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Checks whether a value is a valid confidence score.
 * @param {*} value - Value to inspect.
 * @returns {boolean} True when value is a finite number from 0 to 1 inclusive.
 */
function isConfidenceScore(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
}

/**
 * Checks whether a value is an integer inside a closed range.
 * @param {*} value - Value to inspect.
 * @param {number} min - Minimum accepted value.
 * @param {number} max - Maximum accepted value.
 * @returns {boolean} True when value is an integer in range.
 */
function isIntegerInRange(value, min, max) {
  return Number.isInteger(value) && value >= min && value <= max;
}

/**
 * Checks whether a value can be parsed as an ISO-like timestamp.
 * @param {*} value - Value to inspect.
 * @returns {boolean} True when value is a parseable timestamp string.
 */
function isIsoTimestamp(value) {
  return typeof value === 'string' && value.trim().length > 0 && !Number.isNaN(Date.parse(value));
}

function addMissingFieldErrors(errors, value, fields, label) {
  for (const field of fields) {
    if (!(field in value)) {
      errors.push(`${label} is missing required field: ${field}.`);
    }
  }
}

function addEnumError(errors, value, field, allowed, label) {
  if (field in value && !allowed.includes(value[field])) {
    errors.push(`${label} ${field} must be one of: ${allowed.join(', ')}.`);
  }
}

/**
 * Builds validation results for incident creation payloads.
 * @param {object} incident - Proposed incident input.
 * @returns {{ valid: boolean, errors: string[] }} Validation result.
 */
function validateIncidentCreateData(incident) {
  const errors = [];
  if (!isPlainObject(incident)) {
    return { valid: false, errors: ['Incident must be an object.'] };
  }

  addMissingFieldErrors(errors, incident, INCIDENT_CREATE_REQUIRED_FIELDS, 'Incident');
  addEnumError(errors, incident, 'type', INCIDENT_TYPES, 'Incident');
  addEnumError(errors, incident, 'severity', SEVERITIES, 'Incident');
  addEnumError(errors, incident, 'status', INCIDENT_STATUSES, 'Incident');
  addEnumError(errors, incident, 'hitlStatus', HITL_STATUSES, 'Incident');

  if ('source' in incident && !isPlainObject(incident.source)) {
    errors.push('Incident source must be an object.');
  }
  if ('target' in incident && !isPlainObject(incident.target)) {
    errors.push('Incident target must be an object.');
  }
  if (isPlainObject(incident.target) && !CRITICALITIES.includes(incident.target.criticality)) {
    errors.push(`Incident target.criticality must be one of: ${CRITICALITIES.join(', ')}.`);
  }
  if ('rawEvidence' in incident && !Array.isArray(incident.rawEvidence)) {
    errors.push('Incident rawEvidence must be an array.');
  }
  if ('confidence' in incident && !isConfidenceScore(incident.confidence)) {
    errors.push('Incident confidence must be a number between 0 and 1.');
  }
  if ('riskScore' in incident && !isIntegerInRange(incident.riskScore, 1, 10)) {
    errors.push('Incident riskScore must be an integer between 1 and 10.');
  }
  if ('responseLevel' in incident && !isIntegerInRange(incident.responseLevel, 1, 5)) {
    errors.push('Incident responseLevel must be an integer between 1 and 5.');
  }
  if ('requiresHITL' in incident && typeof incident.requiresHITL !== 'boolean') {
    errors.push('Incident requiresHITL must be a boolean.');
  }
  if ('mlRecommendation' in incident && incident.mlRecommendation !== null && !ML_RECOMMENDATIONS.includes(incident.mlRecommendation)) {
    errors.push(`Incident mlRecommendation must be null or one of: ${ML_RECOMMENDATIONS.join(', ')}.`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Builds validation results for partial incident updates.
 * @param {object} updates - Partial incident fields to update.
 * @returns {{ valid: boolean, errors: string[] }} Validation result.
 */
function validateIncidentUpdates(updates) {
  const errors = [];
  if (!isPlainObject(updates)) {
    return { valid: false, errors: ['Incident updates must be an object.'] };
  }

  addEnumError(errors, updates, 'type', INCIDENT_TYPES, 'Incident');
  addEnumError(errors, updates, 'severity', SEVERITIES, 'Incident');
  addEnumError(errors, updates, 'status', INCIDENT_STATUSES, 'Incident');
  addEnumError(errors, updates, 'hitlStatus', HITL_STATUSES, 'Incident');
  if ('confidence' in updates && !isConfidenceScore(updates.confidence)) {
    errors.push('Incident confidence must be a number between 0 and 1.');
  }
  if ('riskScore' in updates && !isIntegerInRange(updates.riskScore, 1, 10)) {
    errors.push('Incident riskScore must be an integer between 1 and 10.');
  }
  if ('responseLevel' in updates && !isIntegerInRange(updates.responseLevel, 1, 5)) {
    errors.push('Incident responseLevel must be an integer between 1 and 5.');
  }
  if ('requiresHITL' in updates && typeof updates.requiresHITL !== 'boolean') {
    errors.push('Incident requiresHITL must be a boolean.');
  }
  if ('mlRecommendation' in updates && updates.mlRecommendation !== null && !ML_RECOMMENDATIONS.includes(updates.mlRecommendation)) {
    errors.push(`Incident mlRecommendation must be null or one of: ${ML_RECOMMENDATIONS.join(', ')}.`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Builds validation results for AgentMessageSchema objects.
 * @param {object} message - MessageBus payload to validate.
 * @returns {{ valid: boolean, errors: string[] }} Validation result.
 */
function validateAgentMessage(message) {
  const errors = [];
  if (!isPlainObject(message)) {
    return { valid: false, errors: ['Agent message must be an object.'] };
  }

  addMissingFieldErrors(errors, message, AGENT_MESSAGE_REQUIRED_FIELDS, 'Agent message');
  if ('timestamp' in message && !isIsoTimestamp(message.timestamp)) {
    errors.push('Agent message timestamp must be an ISO8601 timestamp string.');
  }
  if ('source' in message && (typeof message.source !== 'string' || message.source.trim().length === 0)) {
    errors.push('Agent message source must be a non-empty string.');
  }
  if ('eventType' in message && (typeof message.eventType !== 'string' || message.eventType.trim().length === 0)) {
    errors.push('Agent message eventType must be a non-empty string.');
  }
  if ('incidentId' in message && message.incidentId !== null && typeof message.incidentId !== 'string') {
    errors.push('Agent message incidentId must be a string or null.');
  }
  if ('confidence' in message && !isConfidenceScore(message.confidence)) {
    errors.push('Agent message confidence must be a number between 0 and 1.');
  }
  if ('data' in message && !isPlainObject(message.data)) {
    errors.push('Agent message data must be an object.');
  }
  if ('reasoning' in message && typeof message.reasoning !== 'string') {
    errors.push('Agent message reasoning must be a string.');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Builds validation results for ForensicsReportSchema objects.
 * @param {object} report - Forensics report to validate.
 * @returns {{ valid: boolean, errors: string[] }} Validation result.
 */
function validateForensicsReport(report) {
  const errors = [];
  if (!isPlainObject(report)) {
    return { valid: false, errors: ['Forensics report must be an object.'] };
  }

  addMissingFieldErrors(errors, report, Object.keys(FORENSICS_REPORT_SCHEMA), 'Forensics report');
  if ('generatedAt' in report && !isIsoTimestamp(report.generatedAt)) {
    errors.push('Forensics report generatedAt must be an ISO8601 timestamp string.');
  }
  if ('attackTimeline' in report && !Array.isArray(report.attackTimeline)) {
    errors.push('Forensics report attackTimeline must be an array.');
  }
  for (const field of ['affectedSystems', 'indicatorsOfCompromise', 'attackerTTPs', 'containmentActions', 'recommendations', 'rawEvidenceBundle']) {
    if (field in report && !Array.isArray(report[field])) {
      errors.push(`Forensics report ${field} must be an array.`);
    }
  }
  if ('confidenceInAttribution' in report && !isConfidenceScore(report.confidenceInAttribution)) {
    errors.push('Forensics report confidenceInAttribution must be a number between 0 and 1.');
  }

  return { valid: errors.length === 0, errors };
}

module.exports = {
  INCIDENT_SCHEMA,
  AGENT_MESSAGE_SCHEMA,
  FORENSICS_REPORT_SCHEMA,
  INCIDENT_TYPES,
  SEVERITIES,
  INCIDENT_STATUSES,
  CRITICALITIES,
  RESPONSE_ACTIONS,
  RESPONSE_STATUSES,
  HITL_STATUSES,
  ML_RECOMMENDATIONS,
  INCIDENT_CREATE_REQUIRED_FIELDS,
  AGENT_MESSAGE_REQUIRED_FIELDS,
  isPlainObject,
  isConfidenceScore,
  isIntegerInRange,
  isIsoTimestamp,
  validateIncidentCreateData,
  validateIncidentUpdates,
  validateAgentMessage,
  validateForensicsReport
};
