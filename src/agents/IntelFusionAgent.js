const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');
const { combineConfidences } = require('../core/ConfidenceEngine');

const FEED_DIR = path.resolve(process.cwd(), 'data', 'threat-feeds');
const IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_PATTERN = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
const HASH_PATTERN = /\b[a-f0-9]{64}\b/gi;
const CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/gi;

const SYSTEM_PROMPT = `You are AEGIS-IntelFusion, a cyber threat intelligence analyst specializing in indicator enrichment and threat attribution.

Enrichment workflow:
1. Extract all indicators from raw evidence (IPs, domains, file hashes, CVE references)
2. Check every indicator against threat feeds (CISA KEV, AlienVault OTX)
3. Map observed TTPs to MITRE ATT&CK framework
4. Identify threat actor profile if pattern matches known groups
5. Search for historical matches in SharedMemory

Severity escalation rules (APPLY THESE):
- Indicator matches CISA KEV -> escalate severity to CRITICAL immediately
- IP matches known APT infrastructure -> escalate to CRITICAL, flag as targeted attack
- Multiple indicators from same incident match same threat actor -> increase confidence by 0.15
- Pattern matches active ransomware campaign -> escalate to HIGH minimum

Always provide: mitreTechniques[], mitreTactics[], cveIds[], threatActorProfile, recommendations[], updatedConfidence.
Always respond in JSON.`;

function readJson(fileName, fallback) {
  const filePath = path.join(FEED_DIR, fileName);
  if (!fs.existsSync(filePath)) return fallback;
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function addToIndex(index, key, value) {
  const normalized = String(key || '').toLowerCase();
  if (!normalized) return;
  const existing = index.get(normalized) || [];
  existing.push(value);
  index.set(normalized, existing);
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function extractIndicators(lines) {
  const text = Array.isArray(lines) ? lines.join('\n') : String(lines || '');
  const ips = unique(text.match(IP_PATTERN) || []);
  const domains = unique(text.match(DOMAIN_PATTERN) || []).filter((domain) => !/^\d+\./.test(domain));
  const hashes = unique(text.match(HASH_PATTERN) || []);
  const cves = unique((text.match(CVE_PATTERN) || []).map((cve) => cve.toUpperCase()));
  return { ips, domains, hashes, cves };
}

function lookupMany(index, values) {
  return values.flatMap((value) => index.get(String(value).toLowerCase()) || []);
}

function highestSeverity(current, candidate) {
  const rank = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  return rank[candidate] > rank[current] ? candidate : current;
}

function actorBonus(matches) {
  const actors = matches.flatMap((match) => match.tags || [])
    .filter((tag) => /apt|ransom|cobalt|lockbit|clop/i.test(tag));
  return actors.length >= 2 ? 0.15 : 0;
}

function determineSeverity(incident, feedMatches, intelResult) {
  let severity = incident.severity || 'MEDIUM';
  if (feedMatches.some((match) => match.source === 'CISA KEV' || match.severity === 'CRITICAL')) {
    severity = 'CRITICAL';
  }
  if (feedMatches.some((match) => (match.tags || []).some((tag) => /APT/i.test(tag)))) {
    severity = 'CRITICAL';
  }
  if (/ransomware/i.test(intelResult.threatActorProfile || '') || feedMatches.some((match) => match.ransomwareUse === 'Known')) {
    severity = highestSeverity(severity, 'HIGH');
  }
  return severity;
}

function indicatorTasks(indicators) {
  return [
    ...indicators.ips.map((indicator) => ({ indicator, indicatorType: 'IP' })),
    ...indicators.domains.map((indicator) => ({ indicator, indicatorType: 'DOMAIN' })),
    ...indicators.hashes.map((indicator) => ({ indicator, indicatorType: 'FILE_HASH' })),
    ...indicators.cves.map((indicator) => ({ indicator, indicatorType: 'CVE' }))
  ];
}

/**
 * Threat intelligence enrichment agent that correlates incidents with local feeds, MITRE ATT&CK, and history.
 */
class IntelFusionAgent extends AgentBase {
  constructor() {
    super('IntelFusionAgent', SYSTEM_PROMPT, getToolsForAgent('IntelFusionAgent'));
    this.ipFeedIndex = new Map();
    this.domainFeedIndex = new Map();
    this.hashFeedIndex = new Map();
    this.cveFeedIndex = new Map();
    this.reloadTask = null;
  }

  async start() {
    try {
      await super.start();
      this.loadThreatFeeds();
      this.subscribe(EVENTS.THREAT_DETECTED, this.enrichIncident);
      this.subscribe(EVENTS.TASK_ROUTED, this.handleTaskRouted);
      this.reloadTask = cron.schedule('0 0 * * *', () => {
        try {
          this.loadThreatFeeds();
          this.memory.log(this.name, 'THREAT_FEEDS_RELOADED', this.feedStats());
        } catch (error) {
          this.logger.error('scheduled threat feed reload failed', { error: error.message });
        }
      });
      this.memory.log(this.name, 'START_COMPLETE', this.feedStats());
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('IntelFusion start failed', { error: error.message, stack: error.stack });
      throw new Error(`IntelFusionAgent start failed: ${error.message}`);
    }
  }

  async handleTaskRouted(message) {
    try {
      if (message.data.targetAgent !== this.name || message.data.task !== 'ENRICH_INCIDENT') return;
      await this.enrichIncident(message);
    } catch (error) {
      this.memory.log(this.name, 'TASK_ROUTE_ERROR', { error: error.message });
      throw new Error(`handleTaskRouted failed: ${error.message}`);
    }
  }

  loadThreatFeeds() {
    try {
      this.ipFeedIndex = new Map();
      this.domainFeedIndex = new Map();
      this.hashFeedIndex = new Map();
      this.cveFeedIndex = new Map();
      const cisa = readJson('cisa_kev.json', []);
      const otx = readJson('alienvault_otx.json', []);

      cisa.forEach((entry) => addToIndex(this.cveFeedIndex, entry.cveID, {
        indicator: entry.cveID,
        source: 'CISA KEV',
        title: `${entry.vendorProject} ${entry.product}: ${entry.vulnerabilityName}`,
        severity: entry.severity || 'CRITICAL',
        ransomwareUse: entry.knownRansomwareCampaignUse || 'Unknown'
      }));
      otx.forEach((pulse) => (pulse.indicators || []).forEach((item) => {
        const value = {
          indicator: item.indicator,
          source: 'AlienVault OTX',
          title: item.title || pulse.pulseName,
          severity: (item.tags || []).some((tag) => /apt|ransom|c2/i.test(tag)) ? 'HIGH' : 'MEDIUM',
          tags: item.tags || [],
          pulseName: pulse.pulseName
        };
        if (item.type === 'IPv4') addToIndex(this.ipFeedIndex, item.indicator, value);
        if (item.type === 'domain' || item.type === 'hostname') addToIndex(this.domainFeedIndex, item.indicator, value);
        if (/hash/i.test(item.type || '')) addToIndex(this.hashFeedIndex, item.indicator, value);
      }));
      return this.feedStats();
    } catch (error) {
      throw new Error(`loadThreatFeeds failed: ${error.message}`);
    }
  }

  feedStats() {
    return {
      ipIndicators: this.ipFeedIndex.size,
      domainIndicators: this.domainFeedIndex.size,
      hashIndicators: this.hashFeedIndex.size,
      cveIndicators: this.cveFeedIndex.size
    };
  }

  async enrichIncident(message) {
    try {
      const incidentId = message.incidentId || (message.data && message.data.incidentId);
      this.memory.log(this.name, 'ENRICH_INCIDENT_PRE', { incidentId, messageId: message.messageId, eventType: message.eventType });
      if (!incidentId && message.eventType === EVENTS.THREAT_DETECTED) {
        this.memory.log(this.name, 'ENRICH_INCIDENT_DEFERRED', {
          messageId: message.messageId,
          reason: 'Raw threat detection has not been persisted by Orchestrator yet.'
        });
        return;
      }
      const incident = this.memory.getIncident(incidentId);
      if (!incident) throw new Error(`Incident not found: ${incidentId}`);

      const indicators = extractIndicators(incident.rawEvidence);
      const fastMatches = [
        ...lookupMany(this.ipFeedIndex, indicators.ips),
        ...lookupMany(this.domainFeedIndex, indicators.domains),
        ...lookupMany(this.hashFeedIndex, indicators.hashes),
        ...lookupMany(this.cveFeedIndex, indicators.cves)
      ];
      const deepLookups = [];
      for (const task of indicatorTasks(indicators).slice(0, 8)) {
        const result = await this.think('Lookup this indicator using lookup_threat_feed and return JSON only.', task);
        deepLookups.push(result);
      }
      const mitre = await this.think('Map this incident behavior to MITRE ATT&CK using map_to_mitre_attack and return JSON only.', {
        attackBehavior: `${incident.type} ${incident.severity} ${incident.target.service}`,
        observedArtifacts: incident.rawEvidence.concat(indicators.ips, indicators.domains, indicators.cves)
      });
      const deepMatches = deepLookups.flatMap((lookup) => lookup.feedMatches || []);
      const feedMatches = [...fastMatches, ...deepMatches];
      const cveIds = unique([...indicators.cves, ...deepLookups.flatMap((lookup) => lookup.cveIds || [])]);
      const threatActorProfile = deepLookups.map((lookup) => lookup.threatActorProfile).find(Boolean) || null;
      const updatedConfidence = Math.min(0.99, combineConfidences([incident.confidence, mitre.confidence || 0, ...deepLookups.map((lookup) => lookup.confidence || lookup.updatedConfidence || 0)]) + actorBonus(feedMatches));
      const severity = determineSeverity(incident, feedMatches, { threatActorProfile });
      const historicalMatches = this.memory.incidentHistory.filter((oldIncident) => oldIncident.type === incident.type || oldIncident.source.ip === incident.source.ip).length;

      const enrichedIntel = {
        feedMatches,
        cveIds,
        threatActorProfile,
        historicalMatches
      };
      const updatedIncident = this.memory.updateIncident(incident.id, {
        status: 'TRIAGING',
        severity,
        confidence: Number(updatedConfidence.toFixed(4)),
        mitreTechniques: unique([...(incident.mitreTechniques || []), ...(mitre.mitreTechniques || [])]),
        mitreTactics: unique([...(incident.mitreTactics || []), ...(mitre.mitreTactics || [])]),
        enrichedIntel,
        agentNotes: [...(incident.agentNotes || []), { agent: this.name, note: `Enriched ${feedMatches.length} feed match(es), ${cveIds.length} CVE(s).`, timestamp: new Date().toISOString() }]
      });
      this.emit(EVENTS.INTEL_ENRICHED, {
        incidentId: incident.id,
        enrichedIntel,
        severity: updatedIncident.severity,
        confidence: updatedIncident.confidence,
        recommendations: deepLookups.flatMap((lookup) => lookup.recommendations || []),
        reasoning: 'Threat intelligence enrichment completed with local feeds and MITRE mapping.'
      }, incident.id, updatedIncident.confidence);
      this.memory.log(this.name, 'ENRICH_INCIDENT_POST', { incidentId: incident.id, feedMatches: feedMatches.length, severity });
    } catch (error) {
      const incidentId = message.incidentId || (message.data && message.data.incidentId) || null;
      this.memory.log(this.name, 'ENRICH_INCIDENT_ERROR', { incidentId, error: error.message });
      throw new Error(`enrichIncident failed: ${error.message}`);
    }
  }

  stop() {
    if (this.reloadTask && typeof this.reloadTask.stop === 'function') {
      this.reloadTask.stop();
    }
    super.stop();
  }
}

module.exports = IntelFusionAgent;
