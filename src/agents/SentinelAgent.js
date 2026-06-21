const fs = require('fs');
const path = require('path');
const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');
const { generateId } = require('../utils/idGenerator');
const { combineConfidences, adjustForMLAlignment } = require('../core/ConfidenceEngine');

const LOG_DIR = path.resolve(process.cwd(), 'data', 'logs');
const BUILT_IN_RULES = Object.freeze([
  { ruleName: 'sql_injection_keywords', pattern: "UNION\\s+SELECT|DROP\\s+TABLE|1\\s*=\\s*1|OR\\s+'1'\\s*=\\s*'1", logType: 'APPLICATION' },
  { ruleName: 'ransomware_impact', pattern: 'vssadmin\\.exe delete shadows|\\.encrypted\\b|backup service terminated', logType: 'SYSTEM' },
  { ruleName: 'lateral_remote_services', pattern: '(SMB|RDP|port (445|3389)).*workstation-to-workstation', logType: 'NETWORK' },
  { ruleName: 'privilege_escalation', pattern: 'sudo:.*NOT in sudoers|SUID execution|UAC bypass', logType: 'AUTH' },
  { ruleName: 'exfiltration_signals', pattern: 'DNS.*size=[1-9]\\d{2,}|CANARY|exfil-domain', logType: 'NETWORK' }
]);

const SYSTEM_PROMPT = `You are AEGIS-Sentinel, an expert cybersecurity threat detection analyst specializing in log analysis and attack pattern recognition.

Detection thresholds (APPLY EXACTLY - do not deviate):
- BRUTE_FORCE: >=10 failed auth attempts from same IP within 60 seconds
- SQL_INJECTION: Presence of UNION SELECT, DROP TABLE, 1=1--, OR '1'='1 in HTTP parameters
- LATERAL_MOVEMENT: Internal-to-internal SMB or RDP connections between workstations (non-server IPs)
- PRIVILEGE_ESCALATION: sudo by non-admin user, SUID execution, UAC bypass patterns
- DATA_EXFILTRATION: Outbound DNS queries >100 bytes, large file transfers to external IPs, consistent small DNS queries to same external domain
- RANSOMWARE: Mass file extension changes, shadow copy deletion (vssadmin delete shadows), backup service termination

When uncertain, set confidence LOW and explain what would increase your confidence. It is better to flag with low confidence than to miss an attack. It is better to false-positive than false-negative.

Response format: always JSON with: { detectedEvents: [{ type, sourceIP, targetService, confidence, evidence, suggestedMitreTechnique }], overallAssessment, recommendsEscalation }`;

function lazyMlClient() {
  try {
    return require('../integrations/mlServiceClient');
  } catch (error) {
    return {
      scoreBatch: async () => ({
        anomalyScore: 0.5,
        confidence: 0,
        recommendation: 'ESCALATE_TO_LLM',
        flaggedLines: [],
        fallback: true,
        error: error.message
      })
    };
  }
}

function normalizeLines(lines) {
  if (!Array.isArray(lines)) {
    throw new Error('Log batch lines must be an array.');
  }
  return lines.map((line) => (typeof line === 'string' ? line : String(line.content || ''))).filter(Boolean);
}

function inferLogType(fileNameOrType) {
  const value = String(fileNameOrType || '').toLowerCase();
  if (value.includes('auth')) return 'AUTH';
  if (value.includes('network') || value.includes('firewall') || value.includes('dns')) return 'NETWORK';
  if (value.includes('system')) return 'SYSTEM';
  if (value.includes('app') || value.includes('nginx') || value.includes('http')) return 'APPLICATION';
  return 'APPLICATION';
}

function severityFromType(type) {
  if (type === 'RANSOMWARE') return 'CRITICAL';
  if (['LATERAL_MOVEMENT', 'DATA_EXFILTRATION', 'PRIVILEGE_ESCALATION', 'SQL_INJECTION'].includes(type)) return 'HIGH';
  if (type === 'BRUTE_FORCE') return 'HIGH';
  return 'MEDIUM';
}

function targetCriticality(type) {
  return ['RANSOMWARE', 'DATA_EXFILTRATION', 'LATERAL_MOVEMENT'].includes(type) ? 'HIGH' : 'MEDIUM';
}

function makeIncident(event, classification, mlResult, confidence) {
  const type = classification.type || event.type || 'UNKNOWN';
  return {
    type,
    severity: classification.severity || event.severity || severityFromType(type),
    status: 'DETECTING',
    source: { ip: event.sourceIP || '0.0.0.0', port: null, protocol: null, geoLocation: null, hostname: null },
    target: {
      hostname: event.targetHost || 'unknown-host',
      ip: event.targetIP || '0.0.0.0',
      service: event.targetService || 'unknown',
      criticality: targetCriticality(type)
    },
    rawEvidence: event.evidence || [],
    confidence,
    mitreTechniques: [classification.suggestedMitreTechnique || event.suggestedMitreTechnique].filter(Boolean),
    mitreTactics: classification.mitreTactics || [],
    assignedAgents: ['SentinelAgent'],
    mlPreScore: typeof mlResult.anomalyScore === 'number' ? mlResult.anomalyScore : null,
    mlRecommendation: mlResult.recommendation || null
  };
}

/**
 * Threat detection agent that ingests logs, applies ML pre-scoring, and emits standardized threat detections.
 */
class SentinelAgent extends AgentBase {
  constructor() {
    super('SentinelAgent', SYSTEM_PROMPT, getToolsForAgent('SentinelAgent'));
    this.regexCache = [];
    this.fileOffsets = new Map();
    this.pollTimer = null;
    this.discardCount = 0;
    this.watchEntries = [];
  }

  async start() {
    try {
      await super.start();
      this.refreshRegexCache();
      this.initializeFileOffsets();
      this.subscribe(EVENTS.DETECTION_RULES_UPDATED, this.handleDetectionRulesUpdated);
      this.subscribe(EVENTS.LOG_BATCH_RECEIVED, this.handleLogBatchReceived);
      this.pollTimer = setInterval(() => {
        this.scanLogDirectory().catch((error) => this.logger.error('log polling failed', { error: error.message }));
      }, 15000);
      this.memory.log(this.name, 'START_COMPLETE', { compiledRules: this.regexCache.length, pollingDirectory: LOG_DIR });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('Sentinel start failed', { error: error.message, stack: error.stack });
      throw new Error(`SentinelAgent start failed: ${error.message}`);
    }
  }

  async handleDetectionRulesUpdated(message) {
    try {
      this.memory.log(this.name, 'RULE_REFRESH_PRE', { messageId: message.messageId });
      this.refreshRegexCache();
      this.memory.log(this.name, 'RULE_REFRESH_POST', { compiledRules: this.regexCache.length });
    } catch (error) {
      this.memory.log(this.name, 'RULE_REFRESH_ERROR', { error: error.message });
      throw new Error(`handleDetectionRulesUpdated failed: ${error.message}`);
    }
  }

  async handleLogBatchReceived(message) {
    try {
      const records = Array.isArray(message.data.lines) ? message.data.lines : [];
      const lines = normalizeLines(records);
      const logType = message.data.logType || (records[0] && records[0].logType) || inferLogType(message.data.source);
      await this.processLogBatch(lines, logType, message.data.source || message.source || 'message-bus');
    } catch (error) {
      this.memory.log(this.name, 'LOG_BATCH_RECEIVED_ERROR', { error: error.message });
      throw new Error(`handleLogBatchReceived failed: ${error.message}`);
    }
  }

  async processLogBatch(lines, logType, source) {
    try {
      const normalizedLines = normalizeLines(lines);
      if (normalizedLines.length === 0) {
        return { processed: 0, threatsDetected: 0, skipped: true };
      }
      const batchId = generateId();
      this.memory.updateAgentStatus(this.name, 'ANALYZING', `processing ${normalizedLines.length} ${logType} logs`);
      this.memory.log(this.name, 'PROCESS_LOG_BATCH_PRE', { batchId, count: normalizedLines.length, logType, source });

      const mlResult = await lazyMlClient().scoreBatch(normalizedLines, logType, batchId);
      this.emit(EVENTS.ML_PRESCORED, { batchId, logType, source, mlResult, reasoning: 'ML pre-score completed before LLM escalation.' }, null, Math.max(0, Math.min(1, mlResult.confidence || 0)));
      if (mlResult.recommendation === 'DISCARD' && mlResult.confidence > 0.85) {
        this.discardCount += 1;
        this.memory.log(this.name, 'ML_DISCARDED_BATCH', { batchId, discardCount: this.discardCount, mlResult });
        return { processed: normalizedLines.length, threatsDetected: 0, skipped: true, mlResult };
      }
      if (mlResult.recommendation === 'MONITOR') {
        const preFilter = this.runFastPreFilter(normalizedLines);
        this.watchEntries.unshift({ batchId, createdAt: new Date().toISOString(), logType, source, matchedPatterns: preFilter.matchedPatterns, mlResult });
        this.watchEntries = this.watchEntries.slice(0, 200);
        this.memory.log(this.name, 'ML_MONITOR_BATCH', { batchId, matchedPatterns: preFilter.matchedPatterns });
        return { processed: normalizedLines.length, threatsDetected: 0, monitored: true, mlResult };
      }

      const analysis = await this.think('Analyze this log batch using analyze_log_batch. Return valid JSON only.', { batchId, logs: normalizedLines, logType, source });
      const detectedEvents = Array.isArray(analysis.detectedEvents) ? analysis.detectedEvents : [];
      for (const event of detectedEvents) {
        const classification = await this.think('Classify this detected anomaly using classify_attack_type. Return valid JSON only.', { event, logType, source });
        const combined = combineConfidences([mlResult.confidence || 0, event.confidence || analysis.confidence || 0, classification.confidence || 0]);
        const confidence = adjustForMLAlignment(combined, mlResult.anomalyScore, mlResult.recommendation);
        const incident = makeIncident(event, classification, mlResult, confidence);
        this.emit(EVENTS.THREAT_DETECTED, { incident, detectedEvent: event, classification, batchId, source, reasoning: classification.reasoning || analysis.overallAssessment || 'Suspicious log pattern detected.' }, null, confidence);
      }
      this.memory.log(this.name, 'PROCESS_LOG_BATCH_POST', { batchId, threatsDetected: detectedEvents.length });
      return { processed: normalizedLines.length, threatsDetected: detectedEvents.length, mlResult };
    } catch (error) {
      this.memory.log(this.name, 'PROCESS_LOG_BATCH_ERROR', { error: error.message, logType, source });
      this.logger.error('processLogBatch failed', { error: error.message, stack: error.stack });
      throw new Error(`processLogBatch failed: ${error.message}`);
    }
  }

  runFastPreFilter(lines) {
    const normalizedLines = normalizeLines(lines);
    const matchedPatterns = [];
    for (const rule of this.regexCache) {
      if (normalizedLines.some((line) => rule.regex.test(line))) {
        matchedPatterns.push(rule.ruleName);
      }
    }
    return { suspicious: matchedPatterns.length > 0, matchedPatterns };
  }

  refreshRegexCache() {
    const rules = [...BUILT_IN_RULES, ...this.memory.detectionRules];
    this.regexCache = rules.map((rule) => {
      try {
        return { ruleName: rule.ruleName, regex: new RegExp(rule.pattern, 'i') };
      } catch (error) {
        this.logger.warn('Skipping invalid detection rule', { ruleName: rule.ruleName, error: error.message });
        return null;
      }
    }).filter(Boolean);
  }

  initializeFileOffsets() {
    if (!fs.existsSync(LOG_DIR)) {
      return;
    }
    for (const fileName of fs.readdirSync(LOG_DIR).filter((file) => file.endsWith('.log'))) {
      const filePath = path.join(LOG_DIR, fileName);
      const lineCount = fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).length;
      this.fileOffsets.set(filePath, lineCount);
    }
  }

  async scanLogDirectory() {
    try {
      if (!fs.existsSync(LOG_DIR)) {
        fs.mkdirSync(LOG_DIR, { recursive: true });
        return;
      }
      for (const fileName of fs.readdirSync(LOG_DIR).filter((file) => file.endsWith('.log'))) {
        const filePath = path.join(LOG_DIR, fileName);
        const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean);
        const previousOffset = this.fileOffsets.get(filePath) || 0;
        const offset = previousOffset > lines.length ? 0 : previousOffset;
        const newLines = lines.slice(offset);
        this.fileOffsets.set(filePath, lines.length);
        if (newLines.length > 0) {
          await this.processLogBatch(newLines, inferLogType(fileName), `file:${fileName}`);
        }
      }
    } catch (error) {
      this.memory.log(this.name, 'SCAN_LOG_DIRECTORY_ERROR', { error: error.message });
      throw new Error(`scanLogDirectory failed: ${error.message}`);
    }
  }

  stop() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    super.stop();
  }
}

module.exports = SentinelAgent;
