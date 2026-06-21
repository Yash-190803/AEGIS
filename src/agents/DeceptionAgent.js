const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');

const SYSTEM_PROMPT = `You are AEGIS-Deception, a cyber deception specialist. You deploy fake assets to catch attackers who evade rule-based detection.

Key principle: Any interaction with a deception asset is by definition malicious. Legitimate users have no reason to access honeypots, canary files, or fake credentials.

Asset deployment triggers:
- BRUTE_FORCE detected -> deploy FAKE_SSH_SERVER to lure attacker to monitored environment
- SQL_INJECTION detected -> deploy FAKE_DATABASE with appealing but fake data
- Scanning detected -> deploy FAKE_ADMIN_PANEL
- Exfiltration suspected -> deploy CANARY_FILE in likely target directory
- Lateral movement -> deploy FAKE_DOMAIN_CONTROLLER

Attacker profiling from honeypot interactions:
- Command types used -> assess skill level (manual vs automated)
- Tools used -> identify attacker toolkit
- Activity timing -> infer time zone, working hours
- Objectives -> what are they looking for?
- Automation vs manual -> scripted mass attack vs targeted intrusion

The longer an attacker stays in the deception environment, the more intelligence we collect. Only eject if they are about to pivot to a real system.`;

function assetForIncident(type) {
  return {
    BRUTE_FORCE: 'FAKE_SSH_SERVER',
    SQL_INJECTION: 'FAKE_DATABASE',
    DATA_EXFILTRATION: 'CANARY_FILE',
    LATERAL_MOVEMENT: 'FAKE_DOMAIN_CONTROLLER',
    UNKNOWN: 'FAKE_ADMIN_PANEL'
  }[type] || null;
}

function targetNetworkForIncident(incident) {
  const ip = incident.target.ip || '10.0.0.0';
  const parts = ip.split('.');
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : '10.0.0.0/24';
}

/**
 * Cyber deception agent that deploys fake assets and profiles malicious interactions.
 */
class DeceptionAgent extends AgentBase {
  constructor() {
    super('DeceptionAgent', SYSTEM_PROMPT, getToolsForAgent('DeceptionAgent'));
  }

  async start() {
    try {
      await super.start();
      this.subscribe(EVENTS.THREAT_DETECTED, this.handleThreatDetected);
      this.subscribe(EVENTS.INTEL_ENRICHED, this.handleIntelEnriched);
      this.subscribe(EVENTS.HONEYPOT_TRIGGERED, this.handleHoneypotTriggered);
      this.subscribe(EVENTS.TASK_ROUTED, this.handleTaskRouted);
      this.memory.log(this.name, 'START_COMPLETE', { subscriptions: 4 });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('Deception start failed', { error: error.message, stack: error.stack });
      throw new Error(`DeceptionAgent start failed: ${error.message}`);
    }
  }

  async handleTaskRouted(message) {
    try {
      if (message.data.targetAgent !== this.name) return;
      if (message.data.task === 'DEPLOY_DECEPTION') await this.assessDeceptionNeed(message.data.incidentId || message.incidentId);
    } catch (error) {
      this.memory.log(this.name, 'TASK_ROUTE_ERROR', { error: error.message });
      throw new Error(`handleTaskRouted failed: ${error.message}`);
    }
  }

  async handleThreatDetected(message) {
    try {
      const incidentId = message.incidentId || (message.data && message.data.incidentId);
      if (incidentId) await this.assessDeceptionNeed(incidentId);
    } catch (error) {
      this.memory.log(this.name, 'THREAT_DECEPTION_ERROR', { error: error.message });
      throw new Error(`handleThreatDetected failed: ${error.message}`);
    }
  }

  async handleIntelEnriched(message) {
    try {
      const incidentId = message.incidentId || (message.data && message.data.incidentId);
      if (incidentId) await this.assessDeceptionNeed(incidentId);
    } catch (error) {
      this.memory.log(this.name, 'INTEL_DECEPTION_ERROR', { error: error.message });
      throw new Error(`handleIntelEnriched failed: ${error.message}`);
    }
  }

  async handleHoneypotTriggered(message) {
    try {
      const honeypotId = message.data.honeypotId;
      const interactions = message.data.interactionLogs || message.data.interactions || [];
      if (!honeypotId) throw new Error('HONEYPOT_TRIGGERED missing honeypotId.');
      await this.processHoneypotInteraction(honeypotId, interactions);
    } catch (error) {
      this.memory.log(this.name, 'HONEYPOT_TRIGGER_ERROR', { error: error.message });
      throw new Error(`handleHoneypotTriggered failed: ${error.message}`);
    }
  }

  async assessDeceptionNeed(incidentId) {
    try {
      this.memory.log(this.name, 'DECEPTION_ASSESS_PRE', { incidentId });
      const incident = this.memory.getIncident(incidentId);
      if (!incident) throw new Error(`Incident not found: ${incidentId}`);
      const assetType = assetForIncident(incident.type);
      if (!assetType) {
        this.memory.log(this.name, 'DECEPTION_NOT_NEEDED', { incidentId, type: incident.type });
        return null;
      }
      const existing = [...this.memory.activeHoneypots.values()].find((honeypot) => honeypot.associatedIncidentId === incidentId && honeypot.assetType === assetType);
      if (existing) {
        this.memory.log(this.name, 'DECEPTION_ALREADY_DEPLOYED', { incidentId, honeypotId: existing.honeypotId });
        return existing;
      }
      const deployed = await this.deployDeceptionAsset(assetType, incidentId);
      this.memory.log(this.name, 'DECEPTION_ASSESS_POST', { incidentId, assetType, honeypotId: deployed.honeypotId });
      return deployed;
    } catch (error) {
      this.memory.log(this.name, 'DECEPTION_ASSESS_ERROR', { incidentId, error: error.message });
      throw new Error(`assessDeceptionNeed failed: ${error.message}`);
    }
  }

  async deployDeceptionAsset(assetType, incidentId) {
    try {
      const incident = this.memory.getIncident(incidentId);
      if (!incident) throw new Error(`Incident not found: ${incidentId}`);
      this.memory.log(this.name, 'DEPLOY_DECEPTION_PRE', { incidentId, assetType });
      const result = JSON.parse(await this.executeTool('deploy_honeypot', {
        assetType,
        targetNetwork: targetNetworkForIncident(incident),
        associatedIncidentId: incidentId
      }));
      this.emit(EVENTS.DECEPTION_DEPLOYED, {
        incidentId,
        honeypotId: result.honeypotId,
        assetType: result.assetType,
        endpoint: result.endpoint,
        reasoning: `Deployed ${assetType} to observe attacker behavior linked to ${incident.type}.`
      }, incidentId, result.confidence || 0.95);
      this.memory.log(this.name, 'DEPLOY_DECEPTION_POST', { incidentId, honeypotId: result.honeypotId });
      return result;
    } catch (error) {
      this.memory.log(this.name, 'DEPLOY_DECEPTION_ERROR', { incidentId, assetType, error: error.message });
      throw new Error(`deployDeceptionAsset failed: ${error.message}`);
    }
  }

  async processHoneypotInteraction(honeypotId, interactions) {
    try {
      this.memory.log(this.name, 'HONEYPOT_INTERACTION_PRE', { honeypotId, count: interactions.length });
      if (!Array.isArray(interactions)) throw new Error('interactions must be an array.');
      const record = this.memory.activeHoneypots.get(honeypotId);
      if (record) {
        record.interactions = [...(record.interactions || []), ...interactions];
        this.memory.activeHoneypots.set(honeypotId, record);
      }
      const allInteractions = record ? record.interactions : interactions;
      if (allInteractions.length < 5) {
        this.memory.log(this.name, 'HONEYPOT_INTERACTION_ACCUMULATING', { honeypotId, count: allInteractions.length });
        return { profiled: false, count: allInteractions.length };
      }
      const profile = await this.profileAttacker(honeypotId, allInteractions);
      this.memory.log(this.name, 'HONEYPOT_INTERACTION_POST', { honeypotId, profileId: profile.profileId });
      return profile;
    } catch (error) {
      this.memory.log(this.name, 'HONEYPOT_INTERACTION_ERROR', { honeypotId, error: error.message });
      throw new Error(`processHoneypotInteraction failed: ${error.message}`);
    }
  }

  async profileAttacker(honeypotId, interactions) {
    try {
      this.memory.log(this.name, 'PROFILE_ATTACKER_PRE', { honeypotId, count: interactions.length });
      const profile = JSON.parse(await this.executeTool('analyze_honeypot_interaction', { honeypotId, interactionLogs: interactions }));
      this.memory.attackerProfiles.set(honeypotId, profile);
      this.emit(EVENTS.ATTACKER_PROFILED, {
        honeypotId,
        profile,
        reasoning: `Attacker profile generated from ${interactions.length} deception interactions.`
      }, null, profile.confidence || 0.8);
      this.memory.log(this.name, 'PROFILE_ATTACKER_POST', { honeypotId, profileId: profile.profileId });
      return profile;
    } catch (error) {
      this.memory.log(this.name, 'PROFILE_ATTACKER_ERROR', { honeypotId, error: error.message });
      throw new Error(`profileAttacker failed: ${error.message}`);
    }
  }
}

module.exports = DeceptionAgent;