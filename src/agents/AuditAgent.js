const fs = require('fs');
const path = require('path');
const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');
const { generateId } = require('../utils/idGenerator');

const AUDIT_DIR = path.resolve(process.cwd(), 'data', 'reports', 'audit');
const REPORT_DIR = path.resolve(process.cwd(), 'data', 'reports');

const SYSTEM_PROMPT = `You are AEGIS-Audit, a compliance and audit trail specialist.

Your job: maintain a complete, immutable record of everything the system does. Every event that flows through the MessageBus must be captured and stored.

For RESPONSE_EXECUTED and HITL_* events: also write to the compliance log with enhanced detail including chain of custody.

Compliance report format (NIST CSF aligned):
- Identify: What assets were at risk
- Protect: What preventive measures were already in place
- Detect: How and when the threat was detected (time from first indicator to detection)
- Respond: Actions taken and timeline
- Recover: Current status and recovery steps

SLA metrics to calculate:
- Mean Time to Detect (MTTD): time from first log line to THREAT_DETECTED event
- Mean Time to Respond (MTTR): time from THREAT_DETECTED to first response action
- Mean Time to Contain (MTTC): time from THREAT_DETECTED to CONTAINED status`;

function dateStamp() {
  return new Date().toISOString().slice(0, 10);
}

function appendJsonLine(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(value)}\n`);
}

function eventTime(entry) {
  return new Date(entry.timestamp || entry.loggedAt || 0).getTime();
}

function durationMs(start, end) {
  if (!start || !end) return null;
  const duration = eventTime(end) - eventTime(start);
  return Number.isFinite(duration) && duration >= 0 ? duration : null;
}

function formatMs(ms) {
  if (ms === null) return 'not available';
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function markdownCompliance(report) {
  return [
    `# AEGIS Compliance Report ${report.reportId}`,
    '',
    `Incident: ${report.incidentId}`,
    `Generated: ${report.generatedAt}`,
    '',
    '## Identify',
    report.identify,
    '',
    '## Protect',
    report.protect,
    '',
    '## Detect',
    report.detect,
    '',
    '## Respond',
    report.respond,
    '',
    '## Recover',
    report.recover,
    '',
    '## SLA Metrics',
    `- MTTD: ${formatMs(report.slaMetrics.mttdMs)}`,
    `- MTTR: ${formatMs(report.slaMetrics.mttrMs)}`,
    `- MTTC: ${formatMs(report.slaMetrics.mttcMs)}`,
    '',
    '## Chain Of Custody',
    report.chainOfCustody.map((entry) => `- ${entry.timestamp} ${entry.source} ${entry.eventType}`).join('\n') || '- No custody events recorded.'
  ].join('\n');
}

/**
 * Compliance and audit trail agent that records every MessageBus event and generates NIST-aligned reports.
 */
class AuditAgent extends AgentBase {
  constructor() {
    super('AuditAgent', SYSTEM_PROMPT, getToolsForAgent('AuditAgent'));
  }

  async start() {
    try {
      await super.start();
      this.bus.subscribeToAll(this.name, this.handleAnyEvent.bind(this));
      this.memory.log(this.name, 'START_COMPLETE', { subscriptions: Object.keys(EVENTS).length });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('Audit start failed', { error: error.message, stack: error.stack });
      throw new Error(`AuditAgent start failed: ${error.message}`);
    }
  }

  handleAnyEvent(message) {
    try {
      const entry = {
        entryId: generateId(),
        loggedAt: new Date().toISOString(),
        eventType: message.eventType,
        source: message.source,
        incidentId: message.incidentId,
        confidence: message.confidence,
        data: message.data,
        reasoning: message.reasoning,
        messageId: message.messageId,
        timestamp: message.timestamp
      };
      this.memory.addToAuditTrail({ type: 'AUDIT_CAPTURE', ...entry });
      appendJsonLine(path.join(AUDIT_DIR, `audit_${dateStamp()}.jsonl`), entry);
      if (message.eventType === EVENTS.RESPONSE_EXECUTED || message.eventType === EVENTS.RESPONSE_ROLLED_BACK || message.eventType.startsWith('HITL_')) {
        appendJsonLine(path.join(AUDIT_DIR, `compliance_${dateStamp()}.jsonl`), {
          ...entry,
          chainOfCustody: {
            capturedBy: this.name,
            custodyTimestamp: new Date().toISOString(),
            integrityNote: 'Stored as append-only JSONL in AEGIS audit directory.'
          }
        });
      }
    } catch (error) {
      this.logger.error('handleAnyEvent failed', { error: error.message, stack: error.stack });
    }
  }

  async generateComplianceReport(incidentId) {
    try {
      this.memory.log(this.name, 'COMPLIANCE_REPORT_PRE', { incidentId });
      const incident = this.memory.getIncident(incidentId);
      if (!incident) throw new Error(`Incident not found: ${incidentId}`);
      const related = this.memory.auditTrail
        .filter((entry) => entry.incidentId === incidentId || (entry.data && entry.data.incidentId === incidentId))
        .sort((a, b) => eventTime(a) - eventTime(b));
      const firstEvidence = incident.rawEvidence.length > 0 ? { timestamp: incident.createdAt } : related[0];
      const detected = related.find((entry) => entry.eventType === EVENTS.THREAT_DETECTED) || { timestamp: incident.createdAt };
      const firstResponse = related.find((entry) => entry.eventType === EVENTS.RESPONSE_EXECUTED);
      const contained = incident.status === 'CONTAINED' ? { timestamp: incident.updatedAt } : related.find((entry) => entry.data && entry.data.status === 'CONTAINED');
      const report = {
        reportId: generateId(),
        incidentId,
        generatedAt: new Date().toISOString(),
        identify: `Asset at risk: ${incident.target.hostname} (${incident.target.ip}) running ${incident.target.service}, criticality ${incident.target.criticality}.`,
        protect: 'Preventive controls observed include detection rules, known-bad indicator memory, HITL guardrails, and reversible simulated response state.',
        detect: `Threat ${incident.type} was detected with confidence ${incident.confidence}. First indicator to detection: ${formatMs(durationMs(firstEvidence, detected))}.`,
        respond: `AEGIS recorded ${incident.responses.length} response action(s). Current incident status is ${incident.status}.`,
        recover: incident.status === 'CONTAINED' ? 'Validate system integrity, rotate credentials, and close after analyst review.' : 'Continue analyst review and complete containment before closure.',
        slaMetrics: {
          mttdMs: durationMs(firstEvidence, detected),
          mttrMs: durationMs(detected, firstResponse),
          mttcMs: durationMs(detected, contained)
        },
        chainOfCustody: related.map((entry) => ({
          timestamp: entry.timestamp || entry.loggedAt,
          source: entry.source || entry.agent || 'unknown',
          eventType: entry.eventType || entry.event || entry.type,
          messageId: entry.messageId || entry.entryId
        }))
      };
      const directory = path.join(REPORT_DIR, incidentId);
      fs.mkdirSync(directory, { recursive: true });
      fs.writeFileSync(path.join(directory, 'compliance_report.md'), markdownCompliance(report));
      fs.writeFileSync(path.join(directory, 'compliance_report.json'), JSON.stringify(report, null, 2));
      this.emit(EVENTS.COMPLIANCE_REPORT_GENERATED, { incidentId, reportId: report.reportId, slaMetrics: report.slaMetrics, reasoning: 'NIST CSF-aligned compliance report generated.' }, incidentId, 0.95);
      this.memory.log(this.name, 'COMPLIANCE_REPORT_POST', { incidentId, reportId: report.reportId });
      return report;
    } catch (error) {
      this.memory.log(this.name, 'COMPLIANCE_REPORT_ERROR', { incidentId, error: error.message });
      throw new Error(`generateComplianceReport failed: ${error.message}`);
    }
  }
}

module.exports = AuditAgent;