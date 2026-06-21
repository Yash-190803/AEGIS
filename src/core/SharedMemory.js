const config = require('../config/env');
const { generateId } = require('../utils/idGenerator');
const { createLogger } = require('../utils/logger');
const {
  validateIncidentCreateData,
  validateIncidentUpdates,
  isPlainObject
} = require('../constants/schemas');

const logger = createLogger('SharedMemory');
let instance = null;

function now() {
  return new Date().toISOString();
}

function defaultSource(source = {}) {
  return {
    ip: source.ip || '0.0.0.0',
    port: source.port === undefined ? null : source.port,
    protocol: source.protocol || null,
    geoLocation: source.geoLocation || null,
    hostname: source.hostname || null
  };
}

function defaultTarget(target = {}) {
  return {
    hostname: target.hostname || 'unknown-host',
    ip: target.ip || '0.0.0.0',
    service: target.service || 'unknown',
    criticality: target.criticality || 'MEDIUM'
  };
}

function defaultEnrichedIntel(enrichedIntel = {}) {
  return {
    feedMatches: enrichedIntel.feedMatches || [],
    cveIds: enrichedIntel.cveIds || [],
    threatActorProfile: enrichedIntel.threatActorProfile || null,
    historicalMatches: enrichedIntel.historicalMatches || 0
  };
}

function mergeDeep(base, updates) {
  const merged = { ...base };
  for (const [key, value] of Object.entries(updates)) {
    if (isPlainObject(value) && isPlainObject(base[key])) {
      merged[key] = mergeDeep(base[key], value);
    } else {
      merged[key] = value;
    }
  }
  return merged;
}

function sortByPriority(first, second) {
  if ((second.riskScore || 0) !== (first.riskScore || 0)) {
    return (second.riskScore || 0) - (first.riskScore || 0);
  }
  return new Date(first.createdAt).getTime() - new Date(second.createdAt).getTime();
}

/**
 * Shared singleton state store for incidents, agent status, response state, HITL gates, and audit events.
 */
class SharedMemory {
  constructor() {
    if (instance) {
      return instance;
    }

    this.incidents = new Map();
    this.incidentHistory = [];
    this.knownBadIPs = new Map();
    this.knownBadDomains = new Map();
    this.knownBadHashes = new Map();
    this.activeCVEs = new Map();
    this.blockedIPs = new Map();
    this.rateLimitedIPs = new Map();
    this.isolatedMachines = new Map();
    this.activeHoneypots = new Map();
    this.honeypotHits = [];
    this.attackerProfiles = new Map();
    this.detectionRules = [];
    this.baselineMetrics = new Map();
    this.globalThreatLevel = 'LOW';
    this.agentStatus = new Map();
    this.pendingHITL = new Map();
    this.auditTrail = [];
    this.systemStats = {
      totalIncidentsToday: 0,
      totalBlockedToday: 0,
      totalHITLDecisions: 0,
      avgResponseTimeMs: 0,
      startedAt: now()
    };

    instance = this;
  }

  static getInstance() {
    if (!instance) {
      instance = new SharedMemory();
    }
    return instance;
  }

  createIncident(data) {
    if (!isPlainObject(data)) {
      const validation = validateIncidentCreateData(data);
      throw new Error(`Invalid incident data: ${validation.errors.join(' ')}`);
    }

    const timestamp = now();
    const incident = {
      id: generateId(),
      createdAt: timestamp,
      updatedAt: timestamp,
      type: data.type,
      severity: data.severity,
      status: data.status || 'DETECTING',
      source: defaultSource(data.source),
      target: defaultTarget(data.target),
      rawEvidence: [...data.rawEvidence],
      confidence: data.confidence,
      riskScore: data.riskScore || 1,
      responseLevel: data.responseLevel || 1,
      mitreTechniques: data.mitreTechniques || [],
      mitreTactics: data.mitreTactics || [],
      enrichedIntel: defaultEnrichedIntel(data.enrichedIntel),
      responses: data.responses || [],
      forensicsReport: data.forensicsReport || null,
      requiresHITL: data.requiresHITL || false,
      hitlStatus: data.hitlStatus || 'NOT_REQUIRED',
      hitlApprovedBy: data.hitlApprovedBy || null,
      hitlTimestamp: data.hitlTimestamp || null,
      assignedAgents: data.assignedAgents || [],
      agentNotes: data.agentNotes || [],
      mlPreScore: data.mlPreScore === undefined ? null : data.mlPreScore,
      mlRecommendation: data.mlRecommendation === undefined ? null : data.mlRecommendation
    };
    const validation = validateIncidentCreateData(incident);
    if (!validation.valid) {
      throw new Error(`Invalid incident data: ${validation.errors.join(' ')}`);
    }

    this.incidents.set(incident.id, incident);
    this.systemStats.totalIncidentsToday += 1;
    this.enforceMemoryLimits();
    return incident;
  }

  updateIncident(id, updates) {
    const incident = this.incidents.get(id);
    if (!incident) {
      throw new Error(`Incident not found: ${id}`);
    }
    const validation = validateIncidentUpdates(updates);
    if (!validation.valid) {
      throw new Error(`Invalid incident updates: ${validation.errors.join(' ')}`);
    }

    const updatedIncident = mergeDeep(incident, { ...updates, updatedAt: now() });
    this.incidents.set(id, updatedIncident);
    return updatedIncident;
  }

  getIncident(id) {
    return this.incidents.get(id) || null;
  }

  getActiveIncidents() {
    return [...this.incidents.values()]
      .filter((incident) => !['CLOSED', 'FALSE_POSITIVE'].includes(incident.status))
      .sort(sortByPriority);
  }

  archiveIncident(id) {
    const incident = this.incidents.get(id);
    if (!incident) {
      throw new Error(`Incident not found: ${id}`);
    }
    this.incidentHistory.push(incident);
    this.incidents.delete(id);
    return incident;
  }

  enforceMemoryLimits() {
    if (this.incidents.size <= config.maxIncidentsInMemory) {
      return 0;
    }
    const closed = [...this.incidents.values()]
      .filter((incident) => ['CLOSED', 'FALSE_POSITIVE'].includes(incident.status))
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
      .slice(0, 10);
    for (const incident of closed) {
      this.archiveIncident(incident.id);
    }
    return closed.length;
  }

  getPendingHITL() {
    const currentTime = Date.now();
    return [...this.pendingHITL.entries()].map(([incidentId, entry]) => ({
      incidentId,
      ...entry,
      timeRemainingSeconds: Math.max(0, Math.ceil((new Date(entry.expiresAt).getTime() - currentTime) / 1000))
    }));
  }

  addHITLRequest(incidentId, action, reasoning, proposedBy) {
    if (!this.incidents.has(incidentId)) {
      throw new Error(`Cannot add HITL request for missing incident: ${incidentId}`);
    }
    const requestedAt = now();
    const expiresAt = new Date(Date.now() + (config.hitlTimeoutSeconds * 1000)).toISOString();
    const request = { action, requestedAt, expiresAt, reasoning, proposedBy };
    this.pendingHITL.set(incidentId, request);
    this.updateIncident(incidentId, { requiresHITL: true, hitlStatus: 'PENDING' });
    return { incidentId, ...request };
  }

  resolveHITL(incidentId, decision, resolvedBy) {
    const normalizedDecision = String(decision || '').toUpperCase();
    if (!['APPROVED', 'REJECTED', 'TIMEOUT'].includes(normalizedDecision)) {
      throw new Error('HITL decision must be APPROVED, REJECTED, or TIMEOUT.');
    }
    if (!this.pendingHITL.has(incidentId)) {
      throw new Error(`No pending HITL request for incident: ${incidentId}`);
    }

    this.pendingHITL.delete(incidentId);
    this.systemStats.totalHITLDecisions += 1;
    return this.updateIncident(incidentId, {
      hitlStatus: normalizedDecision,
      hitlApprovedBy: normalizedDecision === 'APPROVED' ? resolvedBy : null,
      hitlTimestamp: now()
    });
  }

  addToAuditTrail(entry) {
    const auditEntry = { entryId: generateId(), loggedAt: now(), ...entry };
    this.auditTrail.unshift(auditEntry);
    if (this.auditTrail.length > 10000) {
      this.auditTrail.splice(this.auditTrail.length - 1000, 1000);
    }
    return auditEntry;
  }

  updateAgentStatus(agentName, status, lastAction) {
    const entry = { agentName, status, lastAction, updatedAt: now() };
    this.agentStatus.set(agentName, entry);
    return entry;
  }

  getSystemSnapshot() {
    return {
      globalThreatLevel: this.globalThreatLevel,
      activeIncidentCount: this.getActiveIncidents().length,
      agentStatuses: [...this.agentStatus.values()],
      pendingHITLCount: this.pendingHITL.size,
      blockedIPCount: this.blockedIPs.size,
      activeHoneypotCount: this.activeHoneypots.size,
      systemStats: { ...this.systemStats },
      knownBadIndicatorCount: this.knownBadIPs.size + this.knownBadDomains.size + this.knownBadHashes.size
    };
  }

  addKnownBadIP(ip, source, severity) {
    const entry = { source, addedAt: now(), severity };
    this.knownBadIPs.set(ip, entry);
    return entry;
  }

  isKnownBadIP(ip) {
    return this.knownBadIPs.has(ip);
  }

  addDetectionRule(rule) {
    if (!isPlainObject(rule) || typeof rule.ruleName !== 'string' || rule.ruleName.trim().length === 0) {
      throw new Error('Detection rule must include a non-empty ruleName.');
    }
    this.detectionRules = this.detectionRules.filter((existing) => existing.ruleName !== rule.ruleName);
    this.detectionRules.push(rule);
    return rule;
  }

  log(agentName, event, data) {
    logger.audit(`${agentName} ${event}`, { data });
    return this.addToAuditTrail({ agent: agentName, event, data });
  }
}

module.exports = SharedMemory;
