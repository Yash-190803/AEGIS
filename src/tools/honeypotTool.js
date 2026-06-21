const { EVENTS } = require('../constants/events');

const SCENARIOS = Object.freeze(['BRUTE_FORCE', 'SQL_INJECTION', 'LATERAL_MOVEMENT', 'PRIVILEGE_ESCALATION', 'DATA_EXFILTRATION', 'RANSOMWARE']);
const ASSETS = Object.freeze(['FAKE_SSH_SERVER', 'FAKE_DATABASE', 'FAKE_ADMIN_PANEL', 'CANARY_FILE', 'CANARY_API_KEY', 'FAKE_DOMAIN_CONTROLLER']);
const DOC_IPS = Object.freeze(['203.0.113.45', '198.51.100.77', '192.0.2.24']);

function lazyId() {
  return require('../utils/idGenerator').generateId();
}

function now() {
  return new Date().toISOString();
}

function assertString(value, name) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string.`);
  }
  return value.trim();
}

function arrayOfStrings(value, name) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`${name} must be an array of strings.`);
  }
  return value;
}

function resolveMemory(context) {
  if (context.memory) {
    return context.memory;
  }
  return require('../core/SharedMemory').getInstance();
}

function emit(context, eventType, incidentId, data, reasoning) {
  if (!context.bus) {
    return false;
  }
  return context.bus.emit(eventType, {
    messageId: lazyId(),
    timestamp: now(),
    source: context.agentName || 'HoneypotTool',
    eventType,
    incidentId: incidentId || null,
    confidence: typeof data.confidence === 'number' ? data.confidence : 0.9,
    data,
    reasoning
  });
}

function authLogs(ip) {
  const users = ['root', 'admin', 'backup', 'deploy', 'postgres'];
  return Array.from({ length: 24 }, (_, index) => `Jun 20 10:23:${String(index).padStart(2, '0')} webserver sshd[1234]: Failed password for ${users[index % users.length]} from ${ip} port ${52300 + index} ssh2`)
    .concat(`Jun 20 10:23:59 webserver sshd[1234]: Accepted password for backup from ${ip} port 52399 ssh2`);
}

function scenarioLibrary(name) {
  const ip = DOC_IPS[0];
  const base = {
    BRUTE_FORCE: {
      steps: ['Reconnaissance: SSH service discovered', 'Credential Access: password spray against common accounts', 'Initial Access: weak backup credential accepted'],
      logs: authLogs(ip),
      ttps: ['T1110', 'T1078']
    },
    SQL_INJECTION: {
      steps: ['Reconnaissance: web parameter probing', 'Initial Access: UNION SELECT payload submitted', 'Collection: database table names enumerated'],
      logs: [
        `Jun 20 11:05:01 app01 nginx: ${DOC_IPS[1]} GET /search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- 500`,
        `Jun 20 11:05:03 app01 app: sql error near UNION SELECT from ${DOC_IPS[1]} requestId=req-sqli-001`
      ],
      ttps: ['T1190']
    },
    LATERAL_MOVEMENT: {
      steps: ['Discovery: internal workstation enumeration', 'Lateral Movement: SMB session to peer workstation', 'Credential Access: admin share access attempted'],
      logs: [
        'Jun 20 12:10:01 ids01 netflow: 10.0.0.42 -> 10.0.0.87 SMB port 445 workstation-to-workstation',
        'Jun 20 12:10:08 ids01 netflow: 10.0.0.42 -> 10.0.0.91 RDP port 3389 workstation-to-workstation'
      ],
      ttps: ['T1021', 'T1018']
    },
    PRIVILEGE_ESCALATION: {
      steps: ['Execution: shell opened as service user', 'Privilege Escalation: sudo attempted by non-admin user', 'Persistence: cron task staged'],
      logs: [
        'Jun 20 12:40:11 host01 sudo: deploy : user NOT in sudoers ; TTY=pts/1 ; COMMAND=/bin/bash',
        'Jun 20 12:40:18 host01 audit: SUID execution attempt /tmp/escalate by uid=1007'
      ],
      ttps: ['T1548', 'T1053']
    },
    DATA_EXFILTRATION: {
      steps: ['Collection: sensitive workbook opened', 'Exfiltration: DNS tunneling begins', 'Exfiltration: small chunks leave every 30 seconds'],
      logs: Array.from({ length: 8 }, (_, index) => `Jun 20 14:${String(10 + index).padStart(2, '0')}:00 dns01 query size=${120 + index} host=chunk${index}.data.exfil-domain.203.0.113.99.com from 10.0.0.87`),
      ttps: ['T1048', 'T1567']
    },
    RANSOMWARE: {
      steps: ['Impact: shadow copies deleted', 'Impact: documents renamed with encrypted extension', 'Defense Evasion: backup service stopped'],
      logs: [
        'Jun 20 15:30:01 host42 process: vssadmin.exe delete shadows /all /quiet',
        'Jun 20 15:30:02 host42 service: backup service terminated by unknown process',
        ...Array.from({ length: 12 }, (_, index) => `Jun 20 15:30:${String(10 + index).padStart(2, '0')} fileserver fs: renamed /finance/file${index}.xlsx to /finance/file${index}.xlsx.encrypted`)
      ],
      ttps: ['T1486', 'T1562']
    }
  };
  return base[name];
}

function compileRule(rule) {
  if (!rule || typeof rule.pattern !== 'string') {
    return null;
  }
  return new RegExp(rule.pattern, 'i');
}

function improvementForGap(gap, index, attackTTPs) {
  const lower = gap.toLowerCase();
  const isRansomware = /ransom|shadow|encrypt/.test(lower);
  const isLateral = /lateral|smb|rdp/.test(lower);
  const isExfil = /exfil|dns|canary/.test(lower);
  const isSql = /sql|union|drop/.test(lower);
  const isPriv = /sudo|suid|privilege/.test(lower);
  const technique = attackTTPs[index] || (isRansomware ? 'T1486' : isLateral ? 'T1021' : isExfil ? 'T1048' : isSql ? 'T1190' : isPriv ? 'T1548' : 'T1110');
  const pattern = isRansomware ? '(vssadmin\\.exe delete shadows|\\.encrypted\\b|backup service terminated)' : isLateral ? '(SMB|RDP|port (445|3389)).*workstation-to-workstation' : isExfil ? '(DNS.*size=[1-9]\\d{2,}|CANARY|exfil-domain)' : isSql ? '(UNION\\s+SELECT|DROP\\s+TABLE|1\\s*=\\s*1)' : isPriv ? '(sudo:.*NOT in sudoers|SUID execution|UAC bypass)' : '(Failed password.*from|authentication failure)';
  return {
    ruleName: `redteam_gap_${technique.toLowerCase().replace('.', '_')}_${index + 1}`,
    logType: isSql ? 'APPLICATION' : isExfil || isLateral ? 'NETWORK' : 'AUTH',
    pattern,
    threshold: isRansomware || isExfil ? 1 : 5,
    mitreTechnique: technique,
    falsePositiveRisk: isRansomware || isSql ? 'LOW' : 'MEDIUM',
    rationale: `Closes observed simulation gap: ${gap}`
  };
}

function profileCommands(logs) {
  const corpus = logs.join('\n').toLowerCase();
  const commands = ['whoami', 'id', 'uname', 'net user', 'mimikatz', 'powershell', 'curl', 'wget', 'scp', 'sqlmap']
    .filter((command) => corpus.includes(command));
  const manualSignals = (corpus.match(/\b(ls|cat|whoami|pwd|cd)\b/g) || []).length;
  const automatedSignals = (corpus.match(/sqlmap|hydra|nmap|masscan|gobuster|ffuf/g) || []).length;
  return { commands, manualSignals, automatedSignals };
}

/** Simulates a realistic attack chain and returns generated log artifacts.
 * @param {{ scenario: string, targetProfile?: object }} args - Simulation arguments.
 * @param {object} context - Tool context.
 * @returns {{ scenario: string, steps: string[], logArtifacts: string[], attackTTPs: string[], targetProfile: object, confidence: number }} Simulation result.
 * @throws {Error} If the scenario is invalid. */
function simulate_attack_scenario(args, context = {}) {
  try {
    const scenario = assertString(args && args.scenario, 'scenario').toUpperCase();
    if (!SCENARIOS.includes(scenario)) {
      throw new Error(`scenario must be one of: ${SCENARIOS.join(', ')}.`);
    }
    const plan = scenarioLibrary(scenario);
    const targetProfile = args.targetProfile || { services: ['ssh', 'https', 'smb'], patchLevel: '1_MONTH_BEHIND' };
    const result = { scenario, steps: plan.steps, logArtifacts: plan.logs, attackTTPs: plan.ttps, targetProfile, confidence: 0.91 };
    if (context.memory && context.agentName) {
      context.memory.log(context.agentName, 'ATTACK_SCENARIO_SIMULATED', { scenario, steps: plan.steps.length, artifacts: plan.logs.length });
    }
    return result;
  } catch (error) {
    throw new Error(`simulate_attack_scenario failed: ${error.message}`);
  }
}

/** Identifies which simulated steps are not covered by current detection rules.
 * @param {{ simulationSteps: string[], currentDetectionRules: object[] }} args - Gap analysis arguments.
 * @returns {{ detectionGaps: string[], missedSteps: string[], coveredSteps: string[], invalidRules: string[], coveragePct: number, confidence: number }} Gap analysis.
 * @throws {Error} If inputs are invalid. */
function identify_detection_gaps(args) {
  try {
    const steps = arrayOfStrings(args && args.simulationSteps, 'simulationSteps');
    const rules = Array.isArray(args.currentDetectionRules) ? args.currentDetectionRules : [];
    const invalidRules = [];
    const compiled = rules.map((rule) => {
      try {
        return { rule, regex: compileRule(rule) };
      } catch (error) {
        invalidRules.push(`${rule.ruleName || 'unnamed'}: ${error.message}`);
        return { rule, regex: null };
      }
    }).filter((entry) => entry.regex);
    const coveredSteps = [];
    const missedSteps = [];
    steps.forEach((step) => {
      const matched = compiled.some((entry) => entry.regex.test(step) || (entry.rule.mitreTechnique && step.includes(entry.rule.mitreTechnique)));
      if (matched) coveredSteps.push(step); else missedSteps.push(step);
    });
    const coveragePct = steps.length === 0 ? 100 : Math.round((coveredSteps.length / steps.length) * 100);
    return {
      detectionGaps: missedSteps.map((step) => `No current detection rule clearly covers: ${step}`),
      missedSteps,
      coveredSteps,
      invalidRules,
      coveragePct,
      confidence: invalidRules.length > 0 ? 0.72 : 0.86
    };
  } catch (error) {
    throw new Error(`identify_detection_gaps failed: ${error.message}`);
  }
}

/** Generates concrete detection rules for red-team detection gaps.
 * @param {{ gaps: string[], attackTTPs?: string[] }} args - Rule generation arguments.
 * @returns {{ newRules: object[], validationResult: string, confidence: number }} Generated rule set.
 * @throws {Error} If gaps are invalid. */
function generate_detection_improvements(args) {
  try {
    const gaps = arrayOfStrings(args && args.gaps, 'gaps');
    const attackTTPs = Array.isArray(args.attackTTPs) ? args.attackTTPs : [];
    const newRules = gaps.map((gap, index) => improvementForGap(gap, index, attackTTPs));
    return {
      newRules,
      validationResult: newRules.length > 0 ? `${newRules.length} detection improvement(s) generated.` : 'Current rules covered every simulated step; no new rules generated.',
      confidence: newRules.length > 0 ? 0.84 : 0.9
    };
  } catch (error) {
    throw new Error(`generate_detection_improvements failed: ${error.message}`);
  }
}

/** Deploys a simulated deception asset and records it in SharedMemory.
 * @param {{ assetType: string, targetNetwork?: string, associatedIncidentId?: string }} args - Honeypot deployment arguments.
 * @param {object} context - Tool context.
 * @returns {{ honeypotId: string, assetType: string, status: string, endpoint: string, confidence: number }} Deployment result.
 * @throws {Error} If assetType is invalid. */
function deploy_honeypot(args, context = {}) {
  try {
    const assetType = assertString(args && args.assetType, 'assetType').toUpperCase();
    if (!ASSETS.includes(assetType)) {
      throw new Error(`assetType must be one of: ${ASSETS.join(', ')}.`);
    }
    const memory = resolveMemory(context);
    const honeypotId = lazyId();
    const targetNetwork = args.targetNetwork || '10.0.0.0/24';
    const associatedIncidentId = args.associatedIncidentId || null;
    const endpoint = `${assetType.toLowerCase().replace(/_/g, '-')}.${targetNetwork.replace(/[/.]/g, '-')}.aegis.local`;
    const record = { honeypotId, assetType, targetNetwork, associatedIncidentId, endpoint, deployedAt: now(), status: 'DEPLOYED', interactions: [] };
    memory.activeHoneypots.set(honeypotId, record);
    memory.log(context.agentName || 'HoneypotTool', 'HONEYPOT_DEPLOYED', record);
    emit(context, EVENTS.DECEPTION_DEPLOYED, associatedIncidentId, { ...record, confidence: 0.95 }, `Deployed ${assetType} deception asset for monitored attacker interaction.`);
    return { honeypotId, assetType, status: 'DEPLOYED', endpoint, confidence: 0.95 };
  } catch (error) {
    throw new Error(`deploy_honeypot failed: ${error.message}`);
  }
}

/** Profiles attacker behavior from honeypot interaction logs.
 * @param {{ honeypotId: string, interactionLogs: string[] }} args - Interaction profile arguments.
 * @param {object} context - Tool context.
 * @returns {{ honeypotId: string, skillLevel: string, toolsObserved: string[], objectives: string[], profileId: string, confidence: number }} Attacker profile.
 * @throws {Error} If inputs are invalid. */
function analyze_honeypot_interaction(args, context = {}) {
  try {
    const honeypotId = assertString(args && args.honeypotId, 'honeypotId');
    const interactionLogs = arrayOfStrings(args.interactionLogs, 'interactionLogs');
    const memory = resolveMemory(context);
    const signals = profileCommands(interactionLogs);
    const toolsObserved = signals.commands.concat(signals.automatedSignals > 0 ? ['automated-scanner'] : []);
    const skillLevel = signals.automatedSignals > signals.manualSignals ? 'AUTOMATED_LOW_TO_MEDIUM' : signals.manualSignals >= 3 ? 'MANUAL_INTERACTIVE_MEDIUM' : 'LOW_SIGNAL';
    const objectives = interactionLogs.join(' ').match(/password|credential|secret|token|finance|backup/i) ? ['credential_or_sensitive_data_discovery'] : ['reconnaissance'];
    const profileId = lazyId();
    const profile = { profileId, honeypotId, generatedAt: now(), skillLevel, toolsObserved, objectives, interactionCount: interactionLogs.length, confidence: Math.min(0.95, 0.55 + interactionLogs.length * 0.06) };
    memory.attackerProfiles.set(honeypotId, profile);
    memory.honeypotHits.push(...interactionLogs.map((line) => ({ honeypotId, timestamp: now(), interaction: line })));
    emit(context, EVENTS.ATTACKER_PROFILED, null, profile, `Profiled attacker behavior from ${interactionLogs.length} honeypot interaction(s).`);
    return profile;
  } catch (error) {
    throw new Error(`analyze_honeypot_interaction failed: ${error.message}`);
  }
}

module.exports = {
  simulate_attack_scenario,
  identify_detection_gaps,
  generate_detection_improvements,
  deploy_honeypot,
  analyze_honeypot_interaction
};