const fs = require('fs');
const path = require('path');

const EVIDENCE_TYPES = Object.freeze(['AUTH_LOGS', 'NETWORK_LOGS', 'PROCESS_LOGS', 'FILE_ACCESS_LOGS']);
const LOG_DIR = path.resolve(process.cwd(), 'data', 'logs');

function resolveMemory(context) {
  if (context.memory) {
    return context.memory;
  }
  return require('../core/SharedMemory').getInstance();
}

function assertString(value, name) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string.`);
  }
  return value.trim();
}

function assertEvidenceTypes(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('evidenceTypes must be a non-empty array.');
  }
  const normalized = value.map((item) => assertString(item, 'evidenceType').toUpperCase());
  const invalid = normalized.filter((item) => !EVIDENCE_TYPES.includes(item));
  if (invalid.length > 0) {
    throw new Error(`Unsupported evidence type(s): ${invalid.join(', ')}.`);
  }
  return normalized;
}

function safeReadLogFiles(limitPerFile = 200) {
  if (!fs.existsSync(LOG_DIR)) {
    return [];
  }
  return fs.readdirSync(LOG_DIR)
    .filter((fileName) => fileName.endsWith('.log'))
    .flatMap((fileName) => {
      const filePath = path.join(LOG_DIR, fileName);
      try {
        return fs.readFileSync(filePath, 'utf8').split(/\r?\n/)
          .filter(Boolean)
          .slice(-limitPerFile)
          .map((line) => ({ source: fileName, line }));
      } catch (error) {
        return [{ source: fileName, line: `READ_ERROR: ${error.message}` }];
      }
    });
}

function matchesEvidenceType(line, evidenceTypes) {
  const checks = {
    AUTH_LOGS: /(sshd|login|auth|password|sudo|session)/i,
    NETWORK_LOGS: /(netflow|firewall|dns|http|https|smb|rdp|connection|query)/i,
    PROCESS_LOGS: /(process|cmd\.exe|powershell|vssadmin|service|cron|suid)/i,
    FILE_ACCESS_LOGS: /(audit|read|write|rename|delete|file|\.encrypted|canary)/i
  };
  return evidenceTypes.some((type) => checks[type].test(line));
}

function relatedToIncident(line, incident) {
  const values = [
    incident.source.ip,
    incident.target.ip,
    incident.target.hostname,
    incident.target.service,
    ...incident.rawEvidence.slice(0, 5).map((entry) => entry.split(/\s+/).slice(-4).join(' '))
  ].filter(Boolean);
  return values.some((value) => line.includes(value)) || incident.rawEvidence.some((entry) => entry === line);
}

function collectAuditEvidence(memory, incidentId) {
  return memory.auditTrail
    .filter((entry) => entry.incidentId === incidentId || (entry.data && entry.data.incidentId === incidentId))
    .map((entry) => `AUDIT ${entry.loggedAt} ${entry.type || entry.eventType || entry.event || 'EVENT'} ${JSON.stringify(entry.data || {})}`);
}

function parseTimestamp(text, fallbackIndex) {
  const iso = text.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z/);
  if (iso) {
    return new Date(iso[0]).toISOString();
  }
  const syslog = text.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (!syslog) {
    return new Date(Date.now() + fallbackIndex).toISOString();
  }
  const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const date = new Date();
  date.setMonth(months[syslog[1]], Number(syslog[2]));
  date.setHours(Number(syslog[3]), Number(syslog[4]), Number(syslog[5]), 0);
  return date.toISOString();
}

function inferEvent(line) {
  if (/Failed password|authentication failure|invalid user/i.test(line)) return 'Failed authentication attempt observed';
  if (/Accepted password|login successful|session opened/i.test(line)) return 'Successful authentication observed';
  if (/UNION\s+SELECT|DROP\s+TABLE|1\s*=\s*1/i.test(line)) return 'SQL injection payload observed';
  if (/SMB|RDP|port (445|3389)/i.test(line)) return 'Potential lateral movement connection observed';
  if (/vssadmin|\.encrypted|backup service/i.test(line)) return 'Ransomware impact behavior observed';
  if (/DNS|exfil|CANARY/i.test(line)) return 'Potential exfiltration or deception trigger observed';
  return 'Security-relevant event observed';
}

function inferTechnique(line) {
  if (/Failed password|password spray/i.test(line)) return 'T1110';
  if (/Accepted password|session opened/i.test(line)) return 'T1078';
  if (/UNION\s+SELECT|DROP\s+TABLE|1\s*=\s*1/i.test(line)) return 'T1190';
  if (/SMB|RDP|port (445|3389)/i.test(line)) return 'T1021';
  if (/vssadmin|\.encrypted/i.test(line)) return 'T1486';
  if (/DNS|exfil|CANARY/i.test(line)) return 'T1048';
  if (/sudo|SUID|UAC/i.test(line)) return 'T1548';
  return null;
}

function inferAffectedSystem(line, incident) {
  const hostname = line.match(/\d{2}:\d{2}:\d{2}\s+([a-zA-Z0-9_.-]+)/);
  if (hostname) {
    return hostname[1];
  }
  return incident.target.hostname || incident.target.ip || 'unknown-system';
}

function addTimelineGaps(sortedTimeline) {
  if (sortedTimeline.length < 2) {
    return sortedTimeline;
  }
  const withGaps = [sortedTimeline[0]];
  for (let index = 1; index < sortedTimeline.length; index += 1) {
    const previous = new Date(sortedTimeline[index - 1].timestamp).getTime();
    const current = new Date(sortedTimeline[index].timestamp).getTime();
    const gapMinutes = Math.floor((current - previous) / 60000);
    if (gapMinutes >= 7) {
      withGaps.push({
        timestamp: new Date(previous + 1).toISOString(),
        event: `GAP: No events recorded for approximately ${gapMinutes} minutes`,
        evidence: 'Timeline reconstruction gap',
        affectedSystem: sortedTimeline[index - 1].affectedSystem,
        mitreTechnique: null
      });
    }
    withGaps.push(sortedTimeline[index]);
  }
  return withGaps;
}

/** Collects forensic evidence for an active incident from raw evidence, audit entries, and available log files.
 * @param {{ incidentId: string, evidenceTypes: string[], timeRangeMinutes?: number }} args - Evidence collection arguments.
 * @param {object} context - Tool context.
 * @returns {{ incidentId: string, evidenceBundle: string[], preservedAt: string, evidenceTypes: string[], confidence: number }} Evidence bundle.
 * @throws {Error} If the incident or evidence request is invalid. */
function collect_evidence(args, context = {}) {
  try {
    const memory = resolveMemory(context);
    const incidentId = assertString(args && args.incidentId, 'incidentId');
    const evidenceTypes = assertEvidenceTypes(args.evidenceTypes);
    const incident = memory.getIncident(incidentId);
    if (!incident) {
      throw new Error(`Incident not found: ${incidentId}`);
    }
    const fileEvidence = safeReadLogFiles()
      .filter((item) => matchesEvidenceType(item.line, evidenceTypes) && relatedToIncident(item.line, incident))
      .map((item) => `${item.source}: ${item.line}`);
    const auditEvidence = collectAuditEvidence(memory, incidentId);
    const evidenceBundle = [...incident.rawEvidence, ...fileEvidence, ...auditEvidence]
      .filter((line, index, all) => line && all.indexOf(line) === index);
    const result = {
      incidentId,
      evidenceBundle,
      preservedAt: new Date().toISOString(),
      evidenceTypes,
      timeRangeMinutes: args.timeRangeMinutes || 60,
      confidence: evidenceBundle.length > 0 ? Math.min(0.95, 0.65 + evidenceBundle.length * 0.02) : 0.35
    };
    memory.log(context.agentName || 'ReportGeneratorTool', 'EVIDENCE_COLLECTED', { incidentId, count: evidenceBundle.length, evidenceTypes });
    return result;
  } catch (error) {
    throw new Error(`collect_evidence failed: ${error.message}`);
  }
}

/** Builds a chronological attack timeline from a preserved evidence bundle.
 * @param {{ incidentId: string, evidenceBundle: string[] }} args - Timeline arguments.
 * @param {object} context - Tool context.
 * @returns {{ incidentId: string, attackTimeline: object[], affectedSystems: string[], indicatorsOfCompromise: string[], confidence: number }} Timeline result.
 * @throws {Error} If arguments are invalid. */
function build_attack_timeline(args, context = {}) {
  try {
    const memory = resolveMemory(context);
    const incidentId = assertString(args && args.incidentId, 'incidentId');
    const evidenceBundle = Array.isArray(args.evidenceBundle) ? args.evidenceBundle : [];
    if (evidenceBundle.some((line) => typeof line !== 'string')) {
      throw new Error('evidenceBundle must be an array of strings.');
    }
    const incident = memory.getIncident(incidentId);
    if (!incident) {
      throw new Error(`Incident not found: ${incidentId}`);
    }
    const attackTimeline = addTimelineGaps(evidenceBundle.map((line, index) => ({
      timestamp: parseTimestamp(line, index),
      event: inferEvent(line),
      evidence: line,
      affectedSystem: inferAffectedSystem(line, incident),
      mitreTechnique: inferTechnique(line)
    })).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()));
    const indicators = [...new Set(evidenceBundle.flatMap((line) => line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|CVE-\d{4}-\d{4,7}|[a-f0-9]{64}/gi) || []))];
    const affectedSystems = [...new Set(attackTimeline.map((entry) => entry.affectedSystem).filter(Boolean))];
    const result = {
      incidentId,
      attackTimeline,
      affectedSystems,
      indicatorsOfCompromise: indicators,
      confidence: attackTimeline.length > 0 ? Math.min(0.95, 0.62 + attackTimeline.length * 0.015) : 0.3
    };
    memory.log(context.agentName || 'ReportGeneratorTool', 'ATTACK_TIMELINE_BUILT', { incidentId, events: attackTimeline.length });
    return result;
  } catch (error) {
    throw new Error(`build_attack_timeline failed: ${error.message}`);
  }
}

module.exports = {
  collect_evidence,
  build_attack_timeline
};