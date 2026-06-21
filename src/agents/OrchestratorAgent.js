const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');

const SYSTEM_PROMPT = `You are AEGIS-Orchestrator, the central coordination intelligence of an enterprise cybersecurity platform.

Your responsibilities:
1. Route incoming threat events to the appropriate specialized agents in the correct order
2. Resolve conflicts when agents recommend contradictory actions (always prefer the more cautious option)
3. Manage global threat level based on the full active incident portfolio
4. Serve as the exclusive gateway for all HITL (human-in-the-loop) escalations
5. Ensure pipeline order: Detection -> Intel Enrichment -> Triage -> Response -> Forensics -> Audit

Global threat level rules (APPLY THESE EXACTLY):
- LOW: 0-2 active incidents, all LOW/MEDIUM severity
- MEDIUM: 3-5 active incidents OR any single HIGH severity incident
- HIGH: 6+ active incidents OR any CRITICAL severity incident
- CRITICAL: Active CRITICAL incident AND (lateral movement detected OR data exfiltration in progress)

Conflict resolution rule: When two agents disagree, always choose the MORE cautious recommendation. If one says BLOCK and another says RATE_LIMIT for the same target, escalate to human. Safety > speed, always.

Always respond in valid JSON.`;

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function normalizeThreatPayload(message) {
  const data = message.data && message.data.incident ? message.data.incident : message.data || {};
  const detected = Array.isArray(data.detectedEvents) && data.detectedEvents.length > 0 ? data.detectedEvents[0] : data;
  return {
    type: detected.type || data.type || 'UNKNOWN',
    severity: detected.severity || data.severity || 'MEDIUM',
    status: 'DETECTING',
    source: {
      ip: detected.sourceIP || data.sourceIP || (data.source && data.source.ip) || '0.0.0.0',
      port: detected.sourcePort || null,
      protocol: detected.protocol || null,
      geoLocation: null,
      hostname: detected.sourceHostname || null
    },
    target: {
      hostname: detected.targetHost || (data.target && data.target.hostname) || 'unknown-host',
      ip: detected.targetIP || (data.target && data.target.ip) || '0.0.0.0',
      service: detected.targetService || (data.target && data.target.service) || 'unknown',
      criticality: (data.target && data.target.criticality) || detected.targetCriticality || 'MEDIUM'
    },
    rawEvidence: detected.evidence || data.rawEvidence || data.logs || [],
    confidence: typeof detected.confidence === 'number' ? detected.confidence : message.confidence,
    mitreTechniques: detected.suggestedMitreTechnique ? [detected.suggestedMitreTechnique] : data.mitreTechniques || [],
    mitreTactics: data.mitreTactics || [],
    assignedAgents: ['SentinelAgent', 'OrchestratorAgent'],
    mlPreScore: data.mlPreScore === undefined ? null : data.mlPreScore,
    mlRecommendation: data.mlRecommendation === undefined ? null : data.mlRecommendation
  };
}

function deterministicThreatLevel(incidents) {
  const hasCritical = incidents.some((incident) => incident.severity === 'CRITICAL');
  const hasHigh = incidents.some((incident) => incident.severity === 'HIGH');
  const hasLateralOrExfil = incidents.some((incident) => ['LATERAL_MOVEMENT', 'DATA_EXFILTRATION'].includes(incident.type));
  if (hasCritical && hasLateralOrExfil) return 'CRITICAL';
  if (incidents.length >= 6 || hasCritical) return 'HIGH';
  if (incidents.length >= 3 || hasHigh) return 'MEDIUM';
  return 'LOW';
}

/**
 * Central AEGIS coordination agent responsible for pipeline routing, threat level management, and HITL gating.
 */
class OrchestratorAgent extends AgentBase {
  /**
   * Creates the OrchestratorAgent.
   */
  constructor() {
    super('OrchestratorAgent', SYSTEM_PROMPT, getToolsForAgent('OrchestratorAgent'));
    this.timers = [];
  }

  async start() {
    try {
      await super.start();
      this.subscribe(EVENTS.THREAT_DETECTED, this.handleThreatDetected);
      this.subscribe(EVENTS.INTEL_ENRICHED, this.handleIntelEnriched);
      this.subscribe(EVENTS.INCIDENT_TRIAGED, this.handleIncidentTriaged);
      this.subscribe(EVENTS.RED_TEAM_SIMULATION_COMPLETE, this.handleRedTeamComplete);
      this.subscribe(EVENTS.HONEYPOT_TRIGGERED, this.handleHoneypotTriggered);
      this.subscribe(EVENTS.HITL_APPROVED, this.handleHITLApproved);
      this.subscribe(EVENTS.HITL_REJECTED, this.handleHITLRejected);
      this.subscribe(EVENTS.AGENT_ERROR, this.handleAgentError);
      this.timers.push(setInterval(() => this.updateGlobalThreatLevel().catch((error) => this.logger.error('threat level timer failed', { error: error.message })), 30000));
      this.timers.push(setInterval(() => this.runRedTeamSimulation().catch((error) => this.logger.error('red team timer failed', { error: error.message })), 300000));
      this.timers.push(setInterval(() => this.checkPendingHITL(), 10000));
      this.memory.log(this.name, 'START_COMPLETE', { subscriptions: 8, timers: this.timers.length });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('Orchestrator start failed', { error: error.message, stack: error.stack });
      throw new Error(`OrchestratorAgent start failed: ${error.message}`);
    }
  }

  async handleThreatDetected(message) {
    try {
      this.memory.log(this.name, 'HANDLE_THREAT_DETECTED_PRE', { messageId: message.messageId, incidentId: message.incidentId });
      let incident = message.incidentId ? this.memory.getIncident(message.incidentId) : null;
      if (!incident) {
        incident = this.memory.createIncident(normalizeThreatPayload(message));
      }
      incident = this.memory.updateIncident(incident.id, {
        status: 'ENRICHING',
        assignedAgents: unique([...(incident.assignedAgents || []), 'IntelFusionAgent', 'ForensicsAgent'])
      });
      this.emit(EVENTS.TASK_ROUTED, { targetAgent: 'IntelFusionAgent', task: 'ENRICH_INCIDENT', incidentId: incident.id, reasoning: 'Detection must be enriched before triage.' }, incident.id, message.confidence);
      this.emit(EVENTS.TASK_ROUTED, { targetAgent: 'ForensicsAgent', task: 'START_EVIDENCE_COLLECTION', incidentId: incident.id, reasoning: 'Evidence collection starts immediately at detection time.' }, incident.id, message.confidence);
      this.memory.log(this.name, 'HANDLE_THREAT_DETECTED_POST', { incidentId: incident.id, status: incident.status });
    } catch (error) {
      this.memory.log(this.name, 'HANDLE_THREAT_DETECTED_ERROR', { error: error.message });
      throw new Error(`handleThreatDetected failed: ${error.message}`);
    }
  }

  async handleIntelEnriched(message) {
    try {
      this.memory.log(this.name, 'HANDLE_INTEL_ENRICHED_PRE', { incidentId: message.incidentId });
      const incident = this.memory.getIncident(message.incidentId);
      if (!incident) throw new Error(`Incident not found: ${message.incidentId}`);
      this.memory.updateIncident(incident.id, { status: 'TRIAGING', assignedAgents: unique([...(incident.assignedAgents || []), 'TriageAgent']) });
      this.emit(EVENTS.TASK_ROUTED, { targetAgent: 'TriageAgent', task: 'TRIAGE_INCIDENT', incidentId: incident.id, reasoning: 'Threat intelligence enrichment is complete.' }, incident.id, message.confidence);
      this.memory.log(this.name, 'HANDLE_INTEL_ENRICHED_POST', { incidentId: incident.id });
    } catch (error) {
      this.memory.log(this.name, 'HANDLE_INTEL_ENRICHED_ERROR', { error: error.message });
      throw new Error(`handleIntelEnriched failed: ${error.message}`);
    }
  }

  async handleIncidentTriaged(message) {
    try {
      this.memory.log(this.name, 'HANDLE_TRIAGED_PRE', { incidentId: message.incidentId });
      const incident = this.memory.getIncident(message.incidentId);
      if (!incident) throw new Error(`Incident not found: ${message.incidentId}`);
      const responseLevel = message.data.responseLevel || incident.responseLevel;
      const requiresHITL = Boolean(message.data.requiresHITL || incident.requiresHITL || responseLevel >= 4);
      if (requiresHITL) {
        this.requestHITLApproval(incident.id, message.data.proposedAction || { responseLevel }, message.data.reasoning || 'High-impact response requires approval.');
      } else if (responseLevel <= 3) {
        this.memory.updateIncident(incident.id, { status: 'RESPONDING', requiresHITL: false, hitlStatus: 'NOT_REQUIRED' });
        this.emit(EVENTS.TASK_ROUTED, { targetAgent: 'ResponseAgent', task: 'EXECUTE_RESPONSE', incidentId: incident.id, responseLevel, reasoning: 'Automated response level is within allowed bounds.' }, incident.id, message.confidence);
      }
      this.memory.log(this.name, 'HANDLE_TRIAGED_POST', { incidentId: incident.id, responseLevel, requiresHITL });
    } catch (error) {
      this.memory.log(this.name, 'HANDLE_TRIAGED_ERROR', { error: error.message });
      throw new Error(`handleIncidentTriaged failed: ${error.message}`);
    }
  }

  async handleHITLApproved(message) {
    try {
      await this.handleHITLResponse(message, true);
    } catch (error) {
      throw new Error(`handleHITLApproved failed: ${error.message}`);
    }
  }

  async handleHITLRejected(message) {
    try {
      await this.handleHITLResponse(message, false);
    } catch (error) {
      throw new Error(`handleHITLRejected failed: ${error.message}`);
    }
  }

  async handleHITLResponse(message, approved) {
    try {
      this.memory.log(this.name, 'HANDLE_HITL_RESPONSE_PRE', { incidentId: message.incidentId, approved });
      const incident = this.memory.getIncident(message.incidentId);
      if (!incident) throw new Error(`Incident not found: ${message.incidentId}`);
      const actor = message.data.approvedBy || message.data.rejectedBy || message.source || this.name;
      if (this.memory.pendingHITL.has(incident.id)) {
        this.memory.resolveHITL(incident.id, approved ? 'APPROVED' : 'REJECTED', actor);
      } else {
        this.memory.updateIncident(incident.id, { hitlStatus: approved ? 'APPROVED' : 'REJECTED', hitlApprovedBy: approved ? actor : null, hitlTimestamp: new Date().toISOString() });
      }
      if (approved) {
        this.memory.updateIncident(incident.id, { status: 'RESPONDING' });
        this.emit(EVENTS.TASK_ROUTED, { targetAgent: 'ResponseAgent', task: 'EXECUTE_HITL_APPROVED_RESPONSE', incidentId: incident.id, hitlApproved: true, reasoning: 'Human approval received for high-impact response.' }, incident.id, message.confidence);
      } else {
        this.memory.updateIncident(incident.id, { status: 'ESCALATED' });
      }
      this.memory.log(this.name, 'HANDLE_HITL_RESPONSE_POST', { incidentId: incident.id, approved });
    } catch (error) {
      this.memory.log(this.name, 'HANDLE_HITL_RESPONSE_ERROR', { error: error.message });
      throw new Error(`handleHITLResponse failed: ${error.message}`);
    }
  }

  async updateGlobalThreatLevel() {
    try {
      const incidents = this.memory.getActiveIncidents();
      let nextLevel = deterministicThreatLevel(incidents);
      try {
        const result = await this.think('Return JSON: {"globalThreatLevel":"LOW|MEDIUM|HIGH|CRITICAL","reasoning":"..."} based on the active incident portfolio.', { activeIncidents: incidents });
        if (result && ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(result.globalThreatLevel)) nextLevel = result.globalThreatLevel;
      } catch (error) {
        this.logger.warn('AI threat-level reasoning unavailable; using deterministic rule', { error: error.message });
      }
      if (this.memory.globalThreatLevel !== nextLevel) {
        const previous = this.memory.globalThreatLevel;
        this.memory.globalThreatLevel = nextLevel;
        this.emit(EVENTS.GLOBAL_THREAT_LEVEL_SET, { previousLevel: previous, globalThreatLevel: nextLevel, activeIncidentCount: incidents.length, reasoning: 'Portfolio threat level recalculated.' }, null, 0.9);
      }
    } catch (error) {
      this.memory.log(this.name, 'UPDATE_THREAT_LEVEL_ERROR', { error: error.message });
      throw new Error(`updateGlobalThreatLevel failed: ${error.message}`);
    }
  }

  requestHITLApproval(incidentId, proposedAction, reasoning) {
    try {
      this.memory.log(this.name, 'REQUEST_HITL_PRE', { incidentId, proposedAction });
      const request = this.memory.addHITLRequest(incidentId, proposedAction, reasoning, this.name);
      this.emit(EVENTS.HITL_REQUIRED, { ...request, countdownSeconds: request.timeRemainingSeconds || Math.ceil((new Date(request.expiresAt).getTime() - Date.now()) / 1000), reasoning }, incidentId, 1);
      this.memory.log(this.name, 'REQUEST_HITL_POST', { incidentId, expiresAt: request.expiresAt });
      return request;
    } catch (error) {
      this.memory.log(this.name, 'REQUEST_HITL_ERROR', { incidentId, error: error.message });
      throw new Error(`requestHITLApproval failed: ${error.message}`);
    }
  }

  checkPendingHITL() {
    try {
      for (const request of this.memory.getPendingHITL()) {
        if (request.timeRemainingSeconds > 0) continue;
        this.memory.resolveHITL(request.incidentId, 'TIMEOUT', this.name);
        this.emit(EVENTS.HITL_TIMEOUT, { incidentId: request.incidentId, action: request.action, reasoning: 'Human approval timer expired.' }, request.incidentId, 1);
      }
    } catch (error) {
      this.memory.log(this.name, 'CHECK_HITL_ERROR', { error: error.message });
      this.logger.error('HITL timeout check failed', { error: error.message });
    }
  }

  async runRedTeamSimulation() {
    try {
      if (this.memory.getActiveIncidents().length > 0) return;
      this.emit(EVENTS.RED_TEAM_SIMULATION_STARTED, { scenario: 'BRUTE_FORCE', reason: 'Background hardening while no active incidents exist.', reasoning: 'No active incidents; scheduled red-team validation may run.' }, null, 0.85);
    } catch (error) {
      this.memory.log(this.name, 'RUN_RED_TEAM_ERROR', { error: error.message });
      throw new Error(`runRedTeamSimulation failed: ${error.message}`);
    }
  }

  async handleRedTeamComplete(message) {
    try {
      this.memory.log(this.name, 'RED_TEAM_COMPLETE', { incidentId: message.incidentId, data: message.data });
      await this.updateGlobalThreatLevel();
    } catch (error) {
      throw new Error(`handleRedTeamComplete failed: ${error.message}`);
    }
  }

  async handleHoneypotTriggered(message) {
    try {
      this.memory.log(this.name, 'HONEYPOT_TRIGGERED_PRE', { incidentId: message.incidentId });
      this.emit(EVENTS.TASK_ROUTED, { targetAgent: 'ForensicsAgent', task: 'COLLECT_HONEYPOT_EVIDENCE', incidentId: message.incidentId, reasoning: 'Honeypot interaction is malicious by definition.' }, message.incidentId, message.confidence);
      this.memory.log(this.name, 'HONEYPOT_TRIGGERED_POST', { incidentId: message.incidentId });
    } catch (error) {
      throw new Error(`handleHoneypotTriggered failed: ${error.message}`);
    }
  }

  async handleAgentError(message) {
    try {
      this.memory.log(this.name, 'AGENT_ERROR_OBSERVED', { source: message.data.agentName || message.source, error: message.data.errorMessage });
      this.memory.updateAgentStatus(message.data.agentName || message.source, 'ERROR', message.data.errorMessage || 'agent error');
    } catch (error) {
      this.logger.error('failed to process AGENT_ERROR', { error: error.message });
    }
  }

  stop() {
    this.timers.forEach((timer) => clearInterval(timer));
    this.timers = [];
    super.stop();
  }
}

module.exports = OrchestratorAgent;