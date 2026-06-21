const STRING = 'string';
const NUMBER = 'number';
const BOOLEAN = 'boolean';
const ARRAY = 'array';
const OBJECT = 'object';

const LOG_TYPES = Object.freeze(['AUTH', 'NETWORK', 'SYSTEM', 'APPLICATION', 'FIREWALL']);
const SEVERITIES = Object.freeze(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const INCIDENT_SCENARIOS = Object.freeze(['BRUTE_FORCE', 'SQL_INJECTION', 'LATERAL_MOVEMENT', 'PRIVILEGE_ESCALATION', 'DATA_EXFILTRATION', 'RANSOMWARE']);
const EVIDENCE_TYPES = Object.freeze(['AUTH_LOGS', 'NETWORK_LOGS', 'PROCESS_LOGS', 'FILE_ACCESS_LOGS']);
const HONEYPOT_ASSETS = Object.freeze(['FAKE_SSH_SERVER', 'FAKE_DATABASE', 'FAKE_ADMIN_PANEL', 'CANARY_FILE', 'CANARY_API_KEY', 'FAKE_DOMAIN_CONTROLLER']);

function stringProperty(description, extra = {}) {
  return { type: STRING, description, ...extra };
}

function numberProperty(description, extra = {}) {
  return { type: NUMBER, description, ...extra };
}

function booleanProperty(description) {
  return { type: BOOLEAN, description };
}

function stringArray(description, extra = {}) {
  return { type: ARRAY, items: { type: STRING }, description, ...extra };
}

function objectArray(description) {
  return { type: ARRAY, items: { type: OBJECT }, description };
}

function functionTool(name, description, properties, required = []) {
  return {
    type: 'function',
    function: {
      name,
      description,
      parameters: { type: OBJECT, properties, required }
    }
  };
}

const TOOLS = Object.freeze({
  OrchestratorAgent: Object.freeze([]),
  SentinelAgent: Object.freeze([
    functionTool('analyze_log_batch', 'Analyzes a batch of raw log lines for security anomalies, attack patterns, and suspicious behavior. Returns detected events with confidence scores and evidence.', {
      logs: stringArray('Raw log lines'),
      logType: stringProperty('Log source type', { enum: LOG_TYPES }),
      baseline: {
        type: OBJECT,
        properties: {
          avgRequestsPerMinute: numberProperty('Average requests per minute'),
          knownGoodIPs: stringArray('Known trusted IP addresses')
        }
      }
    }, ['logs', 'logType']),
    functionTool('classify_attack_type', 'Classifies a detected anomaly into a specific MITRE ATT&CK-aligned attack category.', {
      anomalyDescription: stringProperty('Description of suspicious behavior'),
      sourceIP: stringProperty('Observed source IP'),
      targetService: stringProperty('Targeted service'),
      eventCount: numberProperty('Number of related events'),
      timeWindowSeconds: numberProperty('Observation window in seconds')
    }, ['anomalyDescription'])
  ]),
  IntelFusionAgent: Object.freeze([
    functionTool('lookup_threat_feed', 'Searches internal threat intelligence feeds for indicator matches.', {
      indicator: stringProperty('Indicator value'),
      indicatorType: stringProperty('Indicator type', { enum: ['IP', 'DOMAIN', 'FILE_HASH', 'CVE', 'URL'] })
    }, ['indicator', 'indicatorType']),
    functionTool('map_to_mitre_attack', 'Maps observed attack behavior to MITRE ATT&CK techniques and tactics using the technique library.', {
      attackBehavior: stringProperty('Observed attacker behavior'),
      observedArtifacts: stringArray('Observed evidence artifacts')
    }, ['attackBehavior'])
  ]),
  TriageAgent: Object.freeze([
    functionTool('calculate_risk_score', 'Calculates quantitative risk score 1-10 using CVSS-inspired methodology.', {
      threatSeverity: stringProperty('Threat severity', { enum: SEVERITIES }),
      targetCriticality: stringProperty('Target criticality', { enum: SEVERITIES }),
      confidence: numberProperty('Detection confidence', { minimum: 0, maximum: 1 }),
      hasActiveExploit: booleanProperty('Whether active exploitation is known'),
      isInsiderThreat: booleanProperty('Whether insider behavior is indicated'),
      lateralMovementDetected: booleanProperty('Whether lateral movement is detected'),
      dataExfiltrationInProgress: booleanProperty('Whether exfiltration is active')
    }, ['threatSeverity', 'targetCriticality', 'confidence']),
    functionTool('determine_response_level', 'Determines automated response level 1-5. Levels 4 and 5 always set requiresHITL to true.', {
      riskScore: numberProperty('Risk score', { minimum: 1, maximum: 10 }),
      incidentType: stringProperty('Incident type'),
      targetCriticality: stringProperty('Target criticality')
    }, ['riskScore', 'incidentType'])
  ]),
  ResponseAgent: Object.freeze([
    functionTool('execute_alert_only', 'Level 1: Sends alert to dashboard only. No system changes.', {
      message: stringProperty('Alert message'),
      severity: stringProperty('Alert severity'),
      incidentId: stringProperty('Incident ID')
    }, ['message', 'severity', 'incidentId']),
    functionTool('execute_rate_limit', 'Level 2: Rate-limits suspicious source IP. Reversible. Stores rollback token.', {
      ip: stringProperty('Source IP to rate limit'),
      requestsPerMinute: numberProperty('Allowed requests per minute'),
      durationMinutes: numberProperty('Duration in minutes'),
      reason: stringProperty('Reason for rate limit'),
      incidentId: stringProperty('Incident ID')
    }, ['ip', 'requestsPerMinute', 'reason', 'incidentId']),
    functionTool('execute_block_ip', 'Level 3: Blocks source IP at firewall perimeter. Reversible. Requires confidence >= 0.75.', {
      ip: stringProperty('Source IP to block'),
      durationHours: numberProperty('Duration in hours'),
      reason: stringProperty('Reason for block'),
      incidentId: stringProperty('Incident ID')
    }, ['ip', 'reason', 'incidentId']),
    functionTool('rollback_action', 'Reverses a previously executed response action using its rollback token.', {
      actionId: stringProperty('Response action ID'),
      rollbackToken: stringProperty('Rollback authorization token'),
      reason: stringProperty('Rollback reason')
    }, ['actionId', 'rollbackToken', 'reason'])
  ]),
  ForensicsAgent: Object.freeze([
    functionTool('collect_evidence', 'Collects and preserves forensic evidence for an active incident from available log sources.', {
      incidentId: stringProperty('Incident ID'),
      evidenceTypes: { type: ARRAY, items: { type: STRING, enum: EVIDENCE_TYPES } },
      timeRangeMinutes: numberProperty('Lookback window in minutes')
    }, ['incidentId', 'evidenceTypes']),
    functionTool('build_attack_timeline', 'Constructs chronological attack timeline from collected evidence. Gaps in timeline are explicitly noted.', {
      incidentId: stringProperty('Incident ID'),
      evidenceBundle: stringArray('Collected evidence bundle')
    }, ['incidentId', 'evidenceBundle'])
  ]),
  RedTeamAgent: Object.freeze([
    functionTool('simulate_attack_scenario', 'Simulates a realistic cyber attack using MITRE ATT&CK kill chain. Generates realistic log artifacts the attack would produce.', {
      scenario: stringProperty('Attack scenario', { enum: INCIDENT_SCENARIOS }),
      targetProfile: {
        type: OBJECT,
        properties: {
          services: stringArray('Target services'),
          patchLevel: stringProperty('Patch level', { enum: ['CURRENT', '1_MONTH_BEHIND', '6_MONTHS_BEHIND', 'CRITICAL_UNPATCHED'] })
        }
      }
    }, ['scenario']),
    functionTool('identify_detection_gaps', 'Analyzes simulation results against current detection rules to find what SentinelAgent would miss.', {
      simulationSteps: stringArray('Simulation steps'),
      currentDetectionRules: objectArray('Current detection rules')
    }, ['simulationSteps', 'currentDetectionRules']),
    functionTool('generate_detection_improvements', 'Generates concrete new detection rules to close identified gaps. Rules include regex patterns, thresholds, and MITRE technique references.', {
      gaps: stringArray('Detection gaps'),
      attackTTPs: stringArray('Observed attacker TTPs')
    }, ['gaps'])
  ]),
  DeceptionAgent: Object.freeze([
    functionTool('deploy_honeypot', 'Deploys a simulated deception asset to attract and profile attackers.', {
      assetType: stringProperty('Deception asset type', { enum: HONEYPOT_ASSETS }),
      targetNetwork: stringProperty('Target network segment'),
      associatedIncidentId: stringProperty('Associated incident ID')
    }, ['assetType']),
    functionTool('analyze_honeypot_interaction', 'Profiles attacker behavior from honeypot interaction logs to build an attacker behavioral profile.', {
      honeypotId: stringProperty('Honeypot ID'),
      interactionLogs: stringArray('Honeypot interaction logs')
    }, ['honeypotId', 'interactionLogs'])
  ]),
  AuditAgent: Object.freeze([])
});

const HANDLER_MODULES = Object.freeze({
  analyze_log_batch: '../tools/logAnalyzerTool',
  classify_attack_type: '../tools/logAnalyzerTool',
  lookup_threat_feed: '../tools/threatFeedTool',
  map_to_mitre_attack: '../tools/threatFeedTool',
  calculate_risk_score: '../tools/logAnalyzerTool',
  determine_response_level: '../tools/logAnalyzerTool',
  execute_alert_only: '../tools/responseExecutorTool',
  execute_rate_limit: '../tools/responseExecutorTool',
  execute_block_ip: '../tools/responseExecutorTool',
  rollback_action: '../tools/responseExecutorTool',
  collect_evidence: '../tools/reportGeneratorTool',
  build_attack_timeline: '../tools/reportGeneratorTool',
  simulate_attack_scenario: '../tools/honeypotTool',
  identify_detection_gaps: '../tools/honeypotTool',
  generate_detection_improvements: '../tools/honeypotTool',
  deploy_honeypot: '../tools/honeypotTool',
  analyze_honeypot_interaction: '../tools/honeypotTool'
});

/**
 * Returns OpenAI tool definitions for an agent.
 * @param {string} agentName - Agent class name.
 * @returns {object[]} Tool definition array.
 * @throws {Error} If the agent is not registered.
 */
function getToolsForAgent(agentName) {
  if (!Object.prototype.hasOwnProperty.call(TOOLS, agentName)) {
    throw new Error(`No tool registry entry found for agent: ${agentName}`);
  }
  return TOOLS[agentName];
}

/**
 * Finds a tool definition by function name across all agents.
 * @param {string} toolName - OpenAI function tool name.
 * @returns {object | null} Tool definition or null.
 */
function getToolDefinition(toolName) {
  for (const tools of Object.values(TOOLS)) {
    const match = tools.find((tool) => tool.function.name === toolName);
    if (match) {
      return match;
    }
  }
  return null;
}

/**
 * Loads the implementation function for a registered tool.
 * @param {string} toolName - OpenAI function tool name.
 * @returns {Function} Tool handler.
 * @throws {Error} If the tool or exported handler cannot be found.
 */
function loadToolHandler(toolName) {
  const modulePath = HANDLER_MODULES[toolName];
  if (!modulePath || !getToolDefinition(toolName)) {
    throw new Error(`Unknown tool: ${toolName}`);
  }
  const moduleExports = require(modulePath);
  const handler = moduleExports[toolName];
  if (typeof handler !== 'function') {
    throw new Error(`Tool module ${modulePath} does not export handler ${toolName}.`);
  }
  return handler;
}

/**
 * Executes a registered tool handler.
 * @param {string} toolName - OpenAI function tool name.
 * @param {object} args - Tool arguments.
 * @param {object} context - Execution context supplied by AgentBase.
 * @returns {Promise<*>} Tool execution result.
 * @throws {Error} If the tool execution fails.
 */
async function executeTool(toolName, args, context = {}) {
  try {
    const handler = loadToolHandler(toolName);
    return await handler(args, context);
  } catch (error) {
    throw new Error(`ToolRegistry failed to execute ${toolName}: ${error.message}`);
  }
}

const TOOL_HANDLERS = Object.freeze(
  Object.fromEntries(Object.keys(HANDLER_MODULES).map((toolName) => [
    toolName,
    (args, context) => executeTool(toolName, args, context)
  ]))
);

module.exports = {
  TOOLS,
  TOOL_HANDLERS,
  getToolsForAgent,
  getToolDefinition,
  loadToolHandler,
  executeTool
};