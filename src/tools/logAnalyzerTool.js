const { combineConfidences } = require('../core/ConfidenceEngine');

const IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const FAILED_AUTH = /(Failed password|authentication failure|invalid user|login failed)/i;
const SQL_PATTERNS = [/UNION\s+SELECT/i, /DROP\s+TABLE/i, /1\s*=\s*1\s*--?/i, /OR\s+'1'\s*=\s*'1/i, /'\s*OR\s*'/i];
const PRIV_ESC_PATTERNS = [/sudo/i, /SUID/i, /UAC bypass/i, /runas/i, /privilege escalation/i];
const RANSOMWARE_PATTERNS = [/vssadmin\.exe\s+delete\s+shadows/i, /delete shadows\s+\/all/i, /\.encrypted\b/i, /backup.*(stop|terminated|disabled)/i];
const MONTH_INDEX = Object.freeze({ Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 });

function assertStringArray(value, fieldName) {
  if (!Array.isArray(value) || value.some((line) => typeof line !== 'string')) {
    throw new Error(`${fieldName} must be an array of strings.`);
  }
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function parseLogTimestamp(line, index) {
  const match = line.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (!match || MONTH_INDEX[match[1]] === undefined) {
    return index * 1000;
  }
  const date = new Date();
  date.setMonth(MONTH_INDEX[match[1]], Number(match[2]));
  date.setHours(Number(match[3]), Number(match[4]), Number(match[5]), 0);
  return date.getTime();
}

function getIPs(line) {
  return line.match(IP_PATTERN) || [];
}

function isInternalIP(ip) {
  const parts = ip.split('.').map(Number);
  return parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
}

function sourceIPFromLine(line) {
  const fromMatch = line.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/i);
  return fromMatch ? fromMatch[1] : getIPs(line)[0] || '0.0.0.0';
}

function evidence(lines, maxItems = 5) {
  return lines.slice(0, maxItems);
}

function detection(type, sourceIP, targetService, confidence, matchedLines, technique, severity, eventCount, timeWindowSeconds) {
  return {
    type,
    sourceIP,
    targetService,
    confidence,
    evidence: evidence(matchedLines),
    suggestedMitreTechnique: technique,
    severity,
    eventCount,
    timeWindowSeconds
  };
}

function detectBruteForce(lines) {
  const byIP = new Map();
  lines.forEach((line, index) => {
    if (!FAILED_AUTH.test(line)) {
      return;
    }
    const ip = sourceIPFromLine(line);
    const events = byIP.get(ip) || [];
    events.push({ line, time: parseLogTimestamp(line, index) });
    byIP.set(ip, events);
  });

  const detections = [];
  for (const [ip, events] of byIP.entries()) {
    const sorted = events.sort((a, b) => a.time - b.time);
    let bestWindow = [];
    for (let start = 0; start < sorted.length; start += 1) {
      const window = sorted.filter((event) => event.time >= sorted[start].time && event.time - sorted[start].time <= 60000);
      if (window.length > bestWindow.length) {
        bestWindow = window;
      }
    }
    if (bestWindow.length >= 10) {
      detections.push(detection('BRUTE_FORCE', ip, 'ssh', clamp(0.72 + Math.min(bestWindow.length, 50) / 200, 0, 0.96), bestWindow.map((event) => event.line), 'T1110', bestWindow.length >= 25 ? 'HIGH' : 'MEDIUM', bestWindow.length, 60));
    }
  }
  return detections;
}

function detectSQLInjection(lines) {
  const matches = lines.filter((line) => SQL_PATTERNS.some((pattern) => pattern.test(line)));
  if (matches.length === 0) {
    return [];
  }
  return [detection('SQL_INJECTION', sourceIPFromLine(matches[0]), 'web', clamp(0.68 + Math.min(matches.length, 10) / 30, 0, 0.95), matches, 'T1190', matches.some((line) => /DROP\s+TABLE/i.test(line)) ? 'HIGH' : 'MEDIUM', matches.length, 60)];
}

function detectLateralMovement(lines) {
  const matches = lines.filter((line) => {
    const ips = getIPs(line);
    const hasInternalPair = ips.length >= 2 && isInternalIP(ips[0]) && isInternalIP(ips[1]);
    return hasInternalPair && /(SMB|RDP|port\s+(445|3389)|:445|:3389)/i.test(line) && !/server/i.test(line);
  });
  if (matches.length === 0) {
    return [];
  }
  return [detection('LATERAL_MOVEMENT', sourceIPFromLine(matches[0]), /RDP|3389/i.test(matches[0]) ? 'rdp' : 'smb', clamp(0.76 + Math.min(matches.length, 20) / 100, 0, 0.95), matches, 'T1021', 'HIGH', matches.length, 300)];
}

function detectPrivilegeEscalation(lines) {
  const matches = lines.filter((line) => PRIV_ESC_PATTERNS.some((pattern) => pattern.test(line)) && !/sudo.*admin/i.test(line));
  if (matches.length === 0) {
    return [];
  }
  return [detection('PRIVILEGE_ESCALATION', sourceIPFromLine(matches[0]), 'host', 0.78, matches, 'T1548', 'HIGH', matches.length, 300)];
}

function detectDataExfiltration(lines) {
  const dnsLarge = lines.filter((line) => /DNS/i.test(line) && /(bytes|size|length)[=: ]+([1-9]\d{2,})/i.test(line));
  const transfer = lines.filter((line) => /(upload|transfer|sent|egress)/i.test(line) && /(MB|GB|bytes)/i.test(line) && getIPs(line).some((ip) => !isInternalIP(ip)));
  const canary = lines.filter((line) => /CANARY/i.test(line));
  const matches = [...dnsLarge, ...transfer, ...canary];
  if (matches.length === 0) {
    return [];
  }
  return [detection('DATA_EXFILTRATION', sourceIPFromLine(matches[0]), /DNS/i.test(matches[0]) ? 'dns' : 'file', canary.length > 0 ? 0.88 : 0.74, matches, /DNS/i.test(matches[0]) ? 'T1048' : 'T1041', canary.length > 0 || transfer.length > 0 ? 'HIGH' : 'MEDIUM', matches.length, 600)];
}

function detectRansomware(lines) {
  const matches = lines.filter((line) => RANSOMWARE_PATTERNS.some((pattern) => pattern.test(line)));
  if (matches.length === 0) {
    return [];
  }
  const massRenameCount = matches.filter((line) => /\.encrypted\b/i.test(line)).length;
  return [detection('RANSOMWARE', sourceIPFromLine(matches[0]), 'endpoint', clamp(0.84 + Math.min(massRenameCount, 20) / 100, 0, 0.98), matches, 'T1486', massRenameCount >= 5 || matches.some((line) => /vssadmin/i.test(line)) ? 'CRITICAL' : 'HIGH', matches.length, 300)];
}

function severityFromScore(score) {
  if (score >= 8) return 'CRITICAL';
  if (score >= 6) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

/** Analyzes log lines for deterministic security detections and confidence scores.
 * @param {{ logs: string[], logType: string, baseline?: object }} args - Tool arguments.
 * @param {object} context - Optional agent execution context.
 * @returns {{ detectedEvents: object[], overallAssessment: string, recommendsEscalation: boolean, confidence: number }} Detection result.
 * @throws {Error} If inputs are invalid. */
function analyze_log_batch(args, context = {}) {
  try {
    assertStringArray(args.logs, 'logs');
    const detections = [
      ...detectBruteForce(args.logs),
      ...detectSQLInjection(args.logs),
      ...detectLateralMovement(args.logs),
      ...detectPrivilegeEscalation(args.logs),
      ...detectDataExfiltration(args.logs),
      ...detectRansomware(args.logs)
    ].sort((a, b) => b.confidence - a.confidence);
    const confidence = combineConfidences(detections.map((event) => event.confidence));
    const result = {
      detectedEvents: detections,
      overallAssessment: detections.length > 0
        ? `${detections.length} suspicious security pattern(s) detected in ${args.logType || 'UNKNOWN'} logs.`
        : `No deterministic threshold violations detected in ${args.logType || 'UNKNOWN'} logs.`,
      recommendsEscalation: detections.some((event) => ['HIGH', 'CRITICAL'].includes(event.severity)),
      confidence
    };
    if (context.memory && context.agentName) {
      context.memory.log(context.agentName, 'LOG_BATCH_ANALYZED', { count: args.logs.length, detections: detections.length });
    }
    return result;
  } catch (error) {
    throw new Error(`analyze_log_batch failed: ${error.message}`);
  }
}

/** Classifies an anomaly description into a MITRE-aligned incident type.
 * @param {{ anomalyDescription: string, sourceIP?: string, targetService?: string, eventCount?: number, timeWindowSeconds?: number }} args - Tool arguments.
 * @returns {{ type: string, severity: string, confidence: number, suggestedMitreTechnique: string, mitreTactics: string[], reasoning: string }} Classification.
 * @throws {Error} If anomalyDescription is invalid. */
function classify_attack_type(args) {
  try {
    if (!args || typeof args.anomalyDescription !== 'string' || args.anomalyDescription.trim().length === 0) {
      throw new Error('anomalyDescription must be a non-empty string.');
    }
    const text = `${args.anomalyDescription} ${args.targetService || ''}`.toLowerCase();
    const rules = [
      [/ransom|encrypt|shadow/, 'RANSOMWARE', 'CRITICAL', 'T1486', ['Impact']],
      [/lateral|smb|rdp/, 'LATERAL_MOVEMENT', 'HIGH', 'T1021', ['Lateral Movement']],
      [/sql|union select|drop table/, 'SQL_INJECTION', 'HIGH', 'T1190', ['Initial Access']],
      [/exfil|dns|canary|transfer/, 'DATA_EXFILTRATION', 'HIGH', 'T1048', ['Exfiltration']],
      [/sudo|suid|uac|privilege/, 'PRIVILEGE_ESCALATION', 'HIGH', 'T1548', ['Privilege Escalation']],
      [/brute|failed auth|password|ssh/, 'BRUTE_FORCE', 'HIGH', 'T1110', ['Credential Access']]
    ];
    const match = rules.find(([pattern]) => pattern.test(text)) || [null, 'UNKNOWN', 'MEDIUM', 'T1078', ['Defense Evasion']];
    const eventCount = Number(args.eventCount || 1);
    return {
      type: match[1],
      severity: match[2],
      confidence: clamp(0.62 + Math.min(eventCount, 50) / 150, 0, 0.94),
      suggestedMitreTechnique: match[3],
      mitreTactics: match[4],
      sourceIP: args.sourceIP || null,
      targetService: args.targetService || null,
      reasoning: `Classified from anomaly text and ${eventCount} observed event(s) over ${args.timeWindowSeconds || 'unknown'} seconds.`
    };
  } catch (error) {
    throw new Error(`classify_attack_type failed: ${error.message}`);
  }
}

/** Calculates a 1-10 incident risk score using the required additive methodology.
 * @param {object} args - Risk scoring arguments.
 * @returns {{ riskScore: number, severity: string, confidence: number, reasoning: string, modifiers: object }} Risk result.
 * @throws {Error} If required values are invalid. */
function calculate_risk_score(args) {
  try {
    const baseBySeverity = { LOW: 2, MEDIUM: 4.5, HIGH: 6.5, CRITICAL: 9 };
    if (!args || !baseBySeverity[args.threatSeverity] || !baseBySeverity[args.targetCriticality]) {
      throw new Error('threatSeverity and targetCriticality must be LOW, MEDIUM, HIGH, or CRITICAL.');
    }
    const confidence = clamp(Number(args.confidence), 0, 1);
    if (Number.isNaN(confidence)) {
      throw new Error('confidence must be numeric.');
    }
    const modifiers = {
      lateralMovement: args.lateralMovementDetected ? 2 : 0,
      dataExfiltration: args.dataExfiltrationInProgress ? 2 : 0,
      insiderThreat: args.isInsiderThreat ? 1.5 : 0,
      activeExploit: args.hasActiveExploit ? 1.5 : 0,
      criticalTarget: args.targetCriticality === 'CRITICAL' ? 1 : 0,
      isolatedIncident: !args.lateralMovementDetected && !args.dataExfiltrationInProgress ? -1 : 0
    };
    const rawScore = baseBySeverity[args.threatSeverity] + Object.values(modifiers).reduce((sum, value) => sum + value, 0);
    const riskScore = Math.round(clamp(rawScore, 1, 10));
    return {
      riskScore,
      severity: severityFromScore(riskScore),
      confidence,
      reasoning: `Base ${baseBySeverity[args.threatSeverity]} adjusted to ${riskScore} using confirmed incident modifiers.`,
      modifiers
    };
  } catch (error) {
    throw new Error(`calculate_risk_score failed: ${error.message}`);
  }
}

/** Determines response level and HITL requirements from a risk score.
 * @param {{ riskScore: number, incidentType: string, targetCriticality?: string, confidence?: number }} args - Response mapping arguments.
 * @returns {{ responseLevel: number, action: string, requiresHITL: boolean, confidence: number, reasoning: string }} Response decision.
 * @throws {Error} If riskScore is invalid. */
function determine_response_level(args) {
  try {
    const riskScore = Number(args && args.riskScore);
    if (!Number.isFinite(riskScore) || riskScore < 1 || riskScore > 10) {
      throw new Error('riskScore must be a number between 1 and 10.');
    }
    const numericConfidence = args.confidence === undefined ? 1 : Number(args.confidence);
    if (!Number.isFinite(numericConfidence)) {
      throw new Error('confidence must be numeric when provided.');
    }
    const confidence = clamp(numericConfidence, 0, 1);
    let responseLevel = 1;
    let action = 'ALERT_ONLY';
    if (riskScore >= 10) {
      responseLevel = 5;
      action = 'SHUTDOWN';
    } else if (riskScore >= 8) {
      responseLevel = 4;
      action = 'ISOLATE_MACHINE';
    } else if (riskScore >= 6 && confidence >= 0.75) {
      responseLevel = 3;
      action = 'BLOCK_IP';
    } else if (riskScore >= 4 && confidence >= 0.6) {
      responseLevel = 2;
      action = 'RATE_LIMIT';
    }
    return {
      responseLevel,
      action,
      requiresHITL: responseLevel >= 4,
      confidence,
      reasoning: `Risk ${riskScore} for ${args.incidentType || 'UNKNOWN'} maps to level ${responseLevel}; levels 4 and 5 require human approval.`
    };
  } catch (error) {
    throw new Error(`determine_response_level failed: ${error.message}`);
  }
}

module.exports = {
  analyze_log_batch,
  classify_attack_type,
  calculate_risk_score,
  determine_response_level
};
