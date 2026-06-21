const fs = require('fs');
const path = require('path');
const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');
const { generateId } = require('../utils/idGenerator');

const REPORT_DIR = path.resolve(process.cwd(), 'data', 'reports');

const SYSTEM_PROMPT = `You are AEGIS-Forensics, a digital forensics investigator. You collect evidence in real time during incidents - not after the fact.

Evidence preservation priorities:
1. IMMEDIATE (on THREAT_DETECTED): capture current state - what log lines exist right now
2. CONTINUOUS (during incident): collect every related log line from SharedMemory audit trail
3. POST-CONTAINMENT: build complete timeline, identify patient zero, map lateral movement

Timeline rules:
- Every timeline entry MUST have: timestamp, event description, affected system, evidence source
- Gaps in the timeline are explicitly noted: "GAP: No events recorded between T+5m and T+12m"
- Attribution is probabilistic. Use language like "likely", "probably", "evidence suggests" unless evidence is overwhelming.

Executive summary rules (for non-technical stakeholders):
- No unexplained acronyms
- Clearly state: what happened, what data was (or may have been) at risk, what was done
- Confidence level in plain English: "We are highly confident / moderately confident / uncertain"

Technical report rules (for security engineers):
- List ALL IoCs as copy-paste-ready lists
- Include detection signatures for preventing recurrence
- List CVEs exploited if identified

Save reports to: data/reports/{incidentId}/`;

function now() {
  return new Date().toISOString();
}

function confidencePhrase(score) {
  if (score >= 0.8) return 'We are highly confident';
  if (score >= 0.55) return 'We are moderately confident';
  return 'We are uncertain';
}

function markdownReport(report) {
  const timeline = report.attackTimeline.map((entry) => `- ${entry.timestamp} - ${entry.event} (${entry.affectedSystem})\n  Evidence: ${entry.evidence}`).join('\n');
  return [
    `# AEGIS Forensics Report ${report.reportId}`,
    '',
    `Incident: ${report.incidentId}`,
    `Generated: ${report.generatedAt}`,
    '',
    '## Executive Summary',
    report.executiveSummary,
    '',
    '## Attack Timeline',
    timeline || '- No timeline events available.',
    '',
    '## Affected Systems',
    report.affectedSystems.map((item) => `- ${item}`).join('\n') || '- None identified.',
    '',
    '## Indicators of Compromise',
    report.indicatorsOfCompromise.map((item) => `- ${item}`).join('\n') || '- None identified.',
    '',
    '## Attacker TTPs',
    report.attackerTTPs.map((item) => `- ${item}`).join('\n') || '- None identified.',
    '',
    '## Business Impact',
    report.businessImpactAssessment,
    '',
    '## Containment Actions',
    report.containmentActions.map((item) => `- ${item}`).join('\n') || '- No containment actions recorded.',
    '',
    '## Recommendations',
    report.recommendations.map((item) => `- ${item}`).join('\n') || '- Continue monitoring.'
  ].join('\n');
}

function reportPath(incidentId) {
  return path.join(REPORT_DIR, incidentId);
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

/**
 * Digital forensics agent that preserves evidence, reconstructs timelines, and generates incident reports.
 */
class ForensicsAgent extends AgentBase {
  constructor() {
    super('ForensicsAgent', SYSTEM_PROMPT, getToolsForAgent('ForensicsAgent'));
    this.evidenceCache = new Map();
  }

  async start() {
    try {
      await super.start();
      this.subscribe(EVENTS.THREAT_DETECTED, this.handleThreatDetected);
      this.subscribe(EVENTS.TASK_ROUTED, this.handleTaskRouted);
      this.subscribe(EVENTS.INCIDENT_TRIAGED, this.handleIncidentUpdated);
      this.subscribe(EVENTS.RESPONSE_EXECUTED, this.handleIncidentUpdated);
      this.subscribe(EVENTS.HITL_APPROVED, this.handleIncidentUpdated);
      this.memory.log(this.name, 'START_COMPLETE', { subscriptions: 5 });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('Forensics start failed', { error: error.message, stack: error.stack });
      throw new Error(`ForensicsAgent start failed: ${error.message}`);
    }
  }

  async handleTaskRouted(message) {
    try {
      if (message.data.targetAgent !== this.name) return;
      if (String(message.data.task || '').includes('EVIDENCE')) await this.startEvidenceCollection(message.data.incidentId || message.incidentId);
    } catch (error) {
      this.memory.log(this.name, 'TASK_ROUTE_ERROR', { error: error.message });
      throw new Error(`handleTaskRouted failed: ${error.message}`);
    }
  }

  async handleThreatDetected(message) {
    try {
      const incidentId = message.incidentId || (message.data && message.data.incident && message.data.incident.id);
      if (incidentId) await this.startEvidenceCollection(incidentId);
    } catch (error) {
      this.memory.log(this.name, 'THREAT_EVIDENCE_ERROR', { error: error.message });
      throw new Error(`handleThreatDetected failed: ${error.message}`);
    }
  }

  async handleIncidentUpdated(message) {
    try {
      const incidentId = message.incidentId || (message.data && message.data.incidentId);
      if (!incidentId || !this.memory.getIncident(incidentId)) return;
      await this.startEvidenceCollection(incidentId);
      const incident = this.memory.getIncident(incidentId);
      if (incident && ['CONTAINED', 'ESCALATED'].includes(incident.status)) await this.generateReport(incidentId);
    } catch (error) {
      this.memory.log(this.name, 'INCIDENT_UPDATE_FORENSICS_ERROR', { error: error.message });
      throw new Error(`handleIncidentUpdated failed: ${error.message}`);
    }
  }

  async startEvidenceCollection(incidentId) {
    try {
      this.memory.log(this.name, 'EVIDENCE_COLLECTION_PRE', { incidentId });
      const evidence = JSON.parse(await this.executeTool('collect_evidence', {
        incidentId,
        evidenceTypes: ['AUTH_LOGS', 'NETWORK_LOGS', 'PROCESS_LOGS', 'FILE_ACCESS_LOGS'],
        timeRangeMinutes: 60
      }));
      const existing = this.evidenceCache.get(incidentId) || [];
      const merged = unique(existing.concat(evidence.evidenceBundle || []));
      this.evidenceCache.set(incidentId, merged);
      this.emit(EVENTS.EVIDENCE_COLLECTED, { incidentId, evidenceCount: merged.length, confidence: evidence.confidence || 0.8, reasoning: 'Evidence preserved from incident, logs, and audit trail.' }, incidentId, evidence.confidence || 0.8);
      this.memory.log(this.name, 'EVIDENCE_COLLECTION_POST', { incidentId, evidenceCount: merged.length });
      return merged;
    } catch (error) {
      this.memory.log(this.name, 'EVIDENCE_COLLECTION_ERROR', { incidentId, error: error.message });
      throw new Error(`startEvidenceCollection failed: ${error.message}`);
    }
  }

  async buildTimeline(incidentId) {
    try {
      const evidenceBundle = this.evidenceCache.get(incidentId) || await this.startEvidenceCollection(incidentId);
      const timeline = JSON.parse(await this.executeTool('build_attack_timeline', { incidentId, evidenceBundle }));
      this.memory.log(this.name, 'TIMELINE_BUILT', { incidentId, events: timeline.attackTimeline.length });
      return timeline;
    } catch (error) {
      this.memory.log(this.name, 'TIMELINE_ERROR', { incidentId, error: error.message });
      throw new Error(`buildTimeline failed: ${error.message}`);
    }
  }

  async generateReport(incidentId) {
    try {
      this.memory.log(this.name, 'REPORT_GENERATION_PRE', { incidentId });
      const incident = this.memory.getIncident(incidentId);
      if (!incident) throw new Error(`Incident not found: ${incidentId}`);
      const timeline = await this.buildTimeline(incidentId);
      const evidenceBundle = this.evidenceCache.get(incidentId) || [];
      const report = {
        reportId: generateId(),
        incidentId,
        generatedAt: now(),
        executiveSummary: `${confidencePhrase(incident.confidence)} that ${incident.type} affected ${incident.target.hostname}. Evidence suggests the source ${incident.source.ip} targeted ${incident.target.service}. AEGIS preserved evidence and recorded response actions for review.`,
        attackTimeline: timeline.attackTimeline,
        affectedSystems: unique([incident.target.hostname, ...(timeline.affectedSystems || [])]),
        indicatorsOfCompromise: unique([incident.source.ip, ...(timeline.indicatorsOfCompromise || []), ...(incident.enrichedIntel.cveIds || [])]),
        attackerTTPs: unique([...(incident.mitreTechniques || []), ...(incident.mitreTactics || [])]),
        businessImpactAssessment: incident.status === 'CONTAINED' ? 'Threat is currently contained in simulation; review affected credentials and service logs before closure.' : 'Incident remains escalated or under analyst review; business impact may continue until response is approved.',
        containmentActions: incident.responses.map((response) => `${response.action} ${response.target} ${response.status}`),
        recommendations: ['Rotate affected credentials', 'Review firewall and authentication controls', 'Convert confirmed findings into detection rules', 'Validate recovery from known-good backups if ransomware indicators exist'],
        rawEvidenceBundle: evidenceBundle,
        confidenceInAttribution: incident.confidence
      };
      await this.saveReport(incidentId, report);
      this.memory.updateIncident(incidentId, { forensicsReport: report });
      this.emit(EVENTS.FORENSICS_COMPLETE, { incidentId, reportId: report.reportId, confidence: report.confidenceInAttribution, reasoning: 'Forensics report generated and persisted.' }, incidentId, report.confidenceInAttribution);
      this.memory.log(this.name, 'REPORT_GENERATION_POST', { incidentId, reportId: report.reportId });
      return report;
    } catch (error) {
      this.memory.log(this.name, 'REPORT_GENERATION_ERROR', { incidentId, error: error.message });
      throw new Error(`generateReport failed: ${error.message}`);
    }
  }

  async saveReport(incidentId, report) {
    try {
      const directory = reportPath(incidentId);
      fs.mkdirSync(directory, { recursive: true });
      fs.writeFileSync(path.join(directory, 'report.json'), JSON.stringify(report, null, 2));
      fs.writeFileSync(path.join(directory, 'report.md'), markdownReport(report));
      return directory;
    } catch (error) {
      throw new Error(`saveReport failed: ${error.message}`);
    }
  }
}

module.exports = ForensicsAgent;