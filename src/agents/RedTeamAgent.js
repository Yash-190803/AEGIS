const fs = require('fs');
const path = require('path');
const AgentBase = require('../core/AgentBase');
const { getToolsForAgent } = require('../core/ToolRegistry');
const { EVENTS } = require('../constants/events');

const LOG_DIR = path.resolve(process.cwd(), 'data', 'logs');

const SYSTEM_PROMPT = `You are AEGIS-RedTeam, an ethical adversary simulation system. You think like a sophisticated attacker following the MITRE ATT&CK kill chain. Your purpose: find what the Sentinel misses, then fix it.

Simulation process:
1. Plan realistic attack chain: Reconnaissance -> Weaponization -> Delivery -> Exploitation -> Installation -> C2 -> Actions on Objectives
2. Generate realistic log artifacts for each step (exactly what these attacks produce in real log files)
3. Evaluate each step against current Sentinel detection rules
4. Identify precisely which steps would NOT be detected and why
5. Generate concrete detection improvements: regex patterns, thresholds, MITRE technique IDs

Detection improvement format:
{ ruleName, logType, pattern (regex string), threshold, mitreTechnique, falsePositiveRisk: "LOW|MEDIUM|HIGH", rationale }

After simulation, the new rules MUST be pushed to SharedMemory and a DETECTION_RULES_UPDATED event emitted. The Sentinel will pick up the new rules automatically.

Critical: also write the simulated attack logs to data/logs/redteam_sim_{timestamp}.log so Sentinel can validate the new rules actually catch the attack. Run a validation pass after rule generation.

Respond in JSON: { scenario, steps[], logArtifacts[], detectionGaps[], newRules[], validationResult }`;

function nowStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function normalizeScenario(value) {
  const scenario = String(value || 'BRUTE_FORCE').toUpperCase();
  if (scenario === 'RANSOMWARE_LATERAL') return 'RANSOMWARE';
  if (scenario === 'SLOW_EXFILTRATION') return 'DATA_EXFILTRATION';
  return scenario;
}

function validateRegexRules(rules) {
  return rules.map((rule) => {
    try {
      new RegExp(rule.pattern);
      return { ...rule, valid: true };
    } catch (error) {
      return { ...rule, valid: false, validationError: error.message };
    }
  });
}

function localValidation(logArtifacts, rules) {
  const validRules = validateRegexRules(rules).filter((rule) => rule.valid);
  const matchedRules = validRules.filter((rule) => {
    const regex = new RegExp(rule.pattern, 'i');
    return logArtifacts.some((line) => regex.test(line));
  });
  return {
    checkedRules: validRules.length,
    matchedRules: matchedRules.map((rule) => rule.ruleName),
    detected: matchedRules.length > 0,
    confidence: matchedRules.length > 0 ? 0.88 : 0.54
  };
}

/**
 * Ethical adversary simulation agent that improves Sentinel detection coverage through feedback loops.
 */
class RedTeamAgent extends AgentBase {
  constructor() {
    super('RedTeamAgent', SYSTEM_PROMPT, getToolsForAgent('RedTeamAgent'));
  }

  async start() {
    try {
      await super.start();
      this.subscribe(EVENTS.RED_TEAM_SIMULATION_STARTED, this.handleSimulationStarted);
      this.subscribe(EVENTS.TASK_ROUTED, this.handleTaskRouted);
      this.memory.log(this.name, 'START_COMPLETE', { subscriptions: 2 });
    } catch (error) {
      this.memory.updateAgentStatus(this.name, 'ERROR', 'start failed');
      this.logger.error('RedTeam start failed', { error: error.message, stack: error.stack });
      throw new Error(`RedTeamAgent start failed: ${error.message}`);
    }
  }

  async handleSimulationStarted(message) {
    try {
      await this.runSimulation(message.data.scenario || 'BRUTE_FORCE');
    } catch (error) {
      this.memory.log(this.name, 'SIMULATION_EVENT_ERROR', { error: error.message });
      throw new Error(`handleSimulationStarted failed: ${error.message}`);
    }
  }

  async handleTaskRouted(message) {
    try {
      if (message.data.targetAgent !== this.name || !String(message.data.task || '').includes('SIMULATION')) return;
      await this.runSimulation(message.data.scenario || 'BRUTE_FORCE');
    } catch (error) {
      this.memory.log(this.name, 'TASK_ROUTE_ERROR', { error: error.message });
      throw new Error(`handleTaskRouted failed: ${error.message}`);
    }
  }

  async runSimulation(scenario) {
    try {
      const normalizedScenario = normalizeScenario(scenario);
      this.memory.log(this.name, 'SIMULATION_PRE', { scenario: normalizedScenario });
      this.memory.updateAgentStatus(this.name, 'ANALYZING', `red-team ${normalizedScenario}`);
      const simulation = JSON.parse(await this.executeTool('simulate_attack_scenario', {
        scenario: normalizedScenario,
        targetProfile: { services: ['ssh', 'https', 'smb', 'dns'], patchLevel: '1_MONTH_BEHIND' }
      }));
      const logPath = await this.writeSimulationLogs(simulation.logArtifacts || []);
      const gaps = JSON.parse(await this.executeTool('identify_detection_gaps', {
        simulationSteps: simulation.steps || [],
        currentDetectionRules: this.memory.detectionRules
      }));
      const improvements = JSON.parse(await this.executeTool('generate_detection_improvements', {
        gaps: gaps.detectionGaps || [],
        attackTTPs: simulation.attackTTPs || []
      }));
      const validatedRules = validateRegexRules(improvements.newRules || []).filter((rule) => rule.valid);
      validatedRules.forEach((rule) => this.memory.addDetectionRule(rule));
      if (validatedRules.length > 0) {
        this.emit(EVENTS.DETECTION_RULES_UPDATED, { newRules: validatedRules, sourceSimulation: normalizedScenario, reasoning: 'Red-team simulation produced valid detection improvements.' }, null, 0.87);
      }
      const validationResult = localValidation(simulation.logArtifacts || [], validatedRules);
      const report = {
        scenario: normalizedScenario,
        steps: simulation.steps || [],
        logArtifacts: simulation.logArtifacts || [],
        logPath,
        detectionGaps: gaps.detectionGaps || [],
        newRules: validatedRules,
        validationResult,
        confidence: validationResult.confidence
      };
      this.emit(EVENTS.RED_TEAM_SIMULATION_COMPLETE, { ...report, reasoning: 'Red-team feedback loop completed and rules were validated locally.' }, null, validationResult.confidence);
      this.memory.log(this.name, 'SIMULATION_POST', { scenario: normalizedScenario, rulesAdded: validatedRules.length, detected: validationResult.detected });
      return report;
    } catch (error) {
      this.memory.log(this.name, 'SIMULATION_ERROR', { scenario, error: error.message });
      this.logger.error('runSimulation failed', { error: error.message, stack: error.stack });
      throw new Error(`runSimulation failed: ${error.message}`);
    }
  }

  async writeSimulationLogs(logArtifacts) {
    try {
      if (!Array.isArray(logArtifacts) || logArtifacts.some((line) => typeof line !== 'string')) {
        throw new Error('logArtifacts must be an array of strings.');
      }
      fs.mkdirSync(LOG_DIR, { recursive: true });
      const filePath = path.join(LOG_DIR, `redteam_sim_${nowStamp()}.log`);
      fs.writeFileSync(filePath, `${logArtifacts.join('\n')}\n`);
      return filePath;
    } catch (error) {
      throw new Error(`writeSimulationLogs failed: ${error.message}`);
    }
  }
}

module.exports = RedTeamAgent;