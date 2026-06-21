const chalk = require('chalk');
const config = require('./config/env');
const SharedMemory = require('./core/SharedMemory');
const MessageBus = require('./core/MessageBus');
const { EVENTS } = require('./constants/events');
const { generateId } = require('./utils/idGenerator');
const { createLogger } = require('./utils/logger');
const AuditAgent = require('./agents/AuditAgent');
const ForensicsAgent = require('./agents/ForensicsAgent');
const IntelFusionAgent = require('./agents/IntelFusionAgent');
const TriageAgent = require('./agents/TriageAgent');
const ResponseAgent = require('./agents/ResponseAgent');
const SentinelAgent = require('./agents/SentinelAgent');
const DeceptionAgent = require('./agents/DeceptionAgent');
const RedTeamAgent = require('./agents/RedTeamAgent');
const OrchestratorAgent = require('./agents/OrchestratorAgent');
const { startServer } = require('./api/server');

const logger = createLogger('index');

function lazyMLClient() {
  try {
    return require('./integrations/mlServiceClient');
  } catch (error) {
    return {
      checkMLServiceHealth: async () => ({ status: 'unknown', reason: error.message })
    };
  }
}

function banner() {
  return [
    '╔═══════════════════════════════════════════════════════════╗',
    '║   █████╗ ███████╗ ██████╗ ██╗███████╗                    ║',
    '║  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝                    ║',
    '║  ███████║█████╗  ██║  ███╗██║███████╗                    ║',
    '║  ██╔══██║██╔══╝  ██║   ██║██║╚════██║                    ║',
    '║  ██║  ██║███████╗╚██████╔╝██║███████║                    ║',
    '║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝                    ║',
    '║  Autonomous Enterprise Guard & Intelligent Security Swarm ║',
    '║  HCL Tech × OpenAI Hackathon                              ║',
    '╚═══════════════════════════════════════════════════════════╝'
  ].join('\n');
}

async function startAgents(agents) {
  for (const agent of agents) {
    await agent.start();
  }
}

function emitSystemReady(bus) {
  bus.emit(EVENTS.SYSTEM_READY, {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'AEGIS',
    eventType: EVENTS.SYSTEM_READY,
    incidentId: null,
    confidence: 1,
    data: {
      dashboardUrl: `http://localhost:${config.port}`,
      mockMode: config.mockMode,
      agentCount: 9
    },
    reasoning: 'AEGIS startup completed successfully.'
  });
}

/**
 * Starts the complete AEGIS Node.js runtime.
 * @returns {Promise<{ agents: object[], serverBundle: object, mlHealthTimer: NodeJS.Timeout }>} Runtime handles.
 * @throws {Error} If startup fails.
 */
async function main() {
  let mlHealthTimer = null;
  try {
    console.log(chalk.green(banner()));
    const memory = SharedMemory.getInstance();
    const bus = MessageBus.getInstance();
    const mlServiceClient = lazyMLClient();
    const agents = [
      new AuditAgent(),
      new ForensicsAgent(),
      new IntelFusionAgent(),
      new TriageAgent(),
      new ResponseAgent(),
      new SentinelAgent(),
      new DeceptionAgent(),
      new RedTeamAgent(),
      new OrchestratorAgent()
    ];

    await startAgents(agents);
    const serverBundle = await startServer({ agents, mlServiceClient, registerSignalHandlers: false });
    mlHealthTimer = setInterval(() => {
      mlServiceClient.checkMLServiceHealth()
        .then((status) => memory.log('mlServiceClient', 'HEALTH_CHECK', status))
        .catch((error) => logger.warn('ML service health check failed', { error: error.message }));
    }, 30000);

    logger.info(`AEGIS is ready. Dashboard: http://localhost:${config.port}`);
    emitSystemReady(bus);

    const shutdown = (signal) => {
      logger.info(`Received ${signal}; shutting down AEGIS`);
      if (mlHealthTimer) clearInterval(mlHealthTimer);
      serverBundle.stop()
        .then(() => process.exit(0))
        .catch((error) => {
          logger.error('shutdown failed', { error: error.message });
          process.exit(1);
        });
    };
    process.once('SIGINT', () => shutdown('SIGINT'));
    process.once('SIGTERM', () => shutdown('SIGTERM'));
    return { agents, serverBundle, mlHealthTimer };
  } catch (error) {
    if (mlHealthTimer) clearInterval(mlHealthTimer);
    logger.error('AEGIS startup failed', { error: error.message, stack: error.stack });
    throw new Error(`AEGIS startup failed: ${error.message}`);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(chalk.red(error.message));
    process.exit(1);
  });
}

module.exports = {
  main
};