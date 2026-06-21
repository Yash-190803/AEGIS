const path = require('path');
const http = require('http');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { Server } = require('socket.io');
const config = require('../config/env');
const SharedMemory = require('../core/SharedMemory');
const MessageBus = require('../core/MessageBus');
const { EVENTS } = require('../constants/events');
const { generateId } = require('../utils/idGenerator');
const { createLogger } = require('../utils/logger');
const requestLogger = require('./middleware/requestLogger');
const errorHandler = require('./middleware/errorHandler');
const createIncidentsRouter = require('./routes/incidents');
const createAgentsRouter = require('./routes/agents');
const createReportsRouter = require('./routes/reports');
const createHITLRouter = require('./routes/hitl');
const createScenariosRouter = require('./routes/scenarios');
const createInternalRouter = require('./routes/internal');

const logger = createLogger('api-server');
const memory = SharedMemory.getInstance();
const bus = MessageBus.getInstance();

function standardWrapper(message) {
  return {
    eventType: message.eventType,
    timestamp: message.timestamp,
    source: message.source,
    incidentId: message.incidentId,
    confidence: message.confidence,
    data: message.data,
    reasoning: message.reasoning
  };
}

function aggregateTokenUsage(agents = [], openaiClient = null) {
  if (openaiClient && typeof openaiClient.getUsageStats === 'function') {
    return openaiClient.getUsageStats();
  }
  return agents.reduce((totals, agent) => {
    const usage = agent.openai && typeof agent.openai.getUsageStats === 'function'
      ? agent.openai.getUsageStats()
      : { totalInputTokens: 0, totalOutputTokens: 0, totalTokens: 0, estimatedCostUSD: 0 };
    return {
      totalInputTokens: totals.totalInputTokens + usage.totalInputTokens,
      totalOutputTokens: totals.totalOutputTokens + usage.totalOutputTokens,
      totalTokens: totals.totalTokens + usage.totalTokens,
      estimatedCostUSD: Number((totals.estimatedCostUSD + usage.estimatedCostUSD).toFixed(6))
    };
  }, { totalInputTokens: 0, totalOutputTokens: 0, totalTokens: 0, estimatedCostUSD: 0 });
}

async function getMLStatus(runtime) {
  try {
    if (runtime.mlServiceClient && typeof runtime.mlServiceClient.checkMLServiceHealth === 'function') {
      return await runtime.mlServiceClient.checkMLServiceHealth();
    }
    return { status: 'unknown', reason: 'ML service client not attached yet' };
  } catch (error) {
    return { status: 'unhealthy', error: error.message };
  }
}

function recentIndicators(map, limit = 20) {
  return [...map.entries()]
    .map(([indicator, value]) => ({ indicator, ...value }))
    .sort((a, b) => new Date(b.addedAt || 0).getTime() - new Date(a.addedAt || 0).getTime())
    .slice(0, limit);
}

function installAliasRoutes(app) {
  app.get('/api/audit', (req, res, next) => {
    try {
      const limit = Math.max(1, Math.min(parseInt(req.query.limit || '100', 10), 1000));
      const entries = memory.auditTrail
        .filter((entry) => !req.query.incidentId || entry.incidentId === req.query.incidentId || (entry.data && entry.data.incidentId === req.query.incidentId))
        .slice(0, limit);
      res.json(entries);
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/redteam/simulate', (req, res, next) => {
    try {
      const scenario = String(req.body.scenario || 'BRUTE_FORCE').toUpperCase();
      bus.emit(EVENTS.RED_TEAM_SIMULATION_STARTED, {
        messageId: generateId(),
        timestamp: new Date().toISOString(),
        source: 'ServerAliasRoute',
        eventType: EVENTS.RED_TEAM_SIMULATION_STARTED,
        incidentId: null,
        confidence: 1,
        data: { scenario, requestedBy: req.body.requestedBy || 'api' },
        reasoning: `Red-team simulation ${scenario} requested by API alias.`
      });
      res.status(202).json({ accepted: true, scenario, queuedAt: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/deception/honeypots', (req, res, next) => {
    try {
      res.json([...memory.activeHoneypots.values()].map((honeypot) => ({
        ...honeypot,
        hitCount: memory.honeypotHits.filter((hit) => hit.honeypotId === honeypot.honeypotId).length
      })));
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/intel/indicators', (req, res, next) => {
    try {
      res.json({
        counts: {
          ips: memory.knownBadIPs.size,
          domains: memory.knownBadDomains.size,
          hashes: memory.knownBadHashes.size,
          cves: memory.activeCVEs.size
        },
        recent: {
          ips: recentIndicators(memory.knownBadIPs),
          domains: recentIndicators(memory.knownBadDomains),
          hashes: recentIndicators(memory.knownBadHashes),
          cves: recentIndicators(memory.activeCVEs)
        }
      });
    } catch (error) {
      next(error);
    }
  });
}

function attachSocketBridge(io) {
  const snapshotTimer = setInterval(() => io.emit('system_snapshot', memory.getSystemSnapshot()), 5000);
  const heartbeatTimer = setInterval(() => io.emit('agent_heartbeat', [...memory.agentStatus.values()]), 30000);
  bus.subscribeToAll('SocketBridge', (message) => {
    io.emit('aegis_event', standardWrapper(message));
  });
  return () => {
    clearInterval(snapshotTimer);
    clearInterval(heartbeatTimer);
  };
}

/**
 * Creates the Express and Socket.io server bundle without starting the listener.
 * @param {object} runtime - Runtime dependencies such as agents and ML client.
 * @returns {{ app: object, httpServer: object, io: object, stop: Function }} Server bundle.
 */
function createServer(runtime = {}) {
  const app = express();
  const httpServer = http.createServer(app);
  const io = new Server(httpServer, { cors: { origin: [`http://localhost:${config.port}`, `http://127.0.0.1:${config.port}`] } });
  const apiLimiter = rateLimit({ windowMs: 60000, max: 100, standardHeaders: true, legacyHeaders: false });
  const internalLimiter = rateLimit({ windowMs: 60000, max: 1000, standardHeaders: true, legacyHeaders: false });

  app.use(helmet());
  app.use(cors({ origin: [`http://localhost:${config.port}`, `http://127.0.0.1:${config.port}`] }));
  app.use(morgan('combined'));
  app.use(express.json({ limit: '1mb' }));
  app.use(requestLogger);
  app.use(express.static(path.resolve(process.cwd(), 'src', 'dashboard')));
  app.use('/api/internal', internalLimiter, createInternalRouter());
  app.use('/api', apiLimiter);

  app.get('/api/health', async (req, res, next) => {
    try {
      res.json({
        status: 'healthy',
        uptime: process.uptime(),
        activeIncidents: memory.getActiveIncidents().length,
        globalThreatLevel: memory.globalThreatLevel,
        agentCount: runtime.agents ? runtime.agents.length : memory.agentStatus.size,
        mlServiceStatus: await getMLStatus(runtime),
        goIngestorStatus: runtime.goIngestorStatus || 'unknown',
        tokenUsage: aggregateTokenUsage(runtime.agents || [], runtime.openaiClient || null)
      });
    } catch (error) {
      next(error);
    }
  });

  app.use('/api/incidents', createIncidentsRouter());
  app.use('/api/agents', createAgentsRouter());
  app.use('/api/reports', createReportsRouter());
  app.use('/api/hitl', createHITLRouter());
  app.use('/api/scenarios', createScenariosRouter());
  installAliasRoutes(app);
  app.use(errorHandler);

  const cleanupSocketBridge = attachSocketBridge(io);

  async function stop() {
    try {
      cleanupSocketBridge();
      const agents = runtime.agents || [];
      for (const agent of agents) {
        if (agent && typeof agent.stop === 'function') agent.stop();
      }
      await new Promise((resolve, reject) => {
        io.close();
        httpServer.close((error) => (error ? reject(error) : resolve()));
      });
      logger.info('AEGIS shutdown complete');
    } catch (error) {
      logger.error('shutdown failed', { error: error.message, stack: error.stack });
      throw error;
    }
  }

  return { app, httpServer, io, stop };
}

/**
 * Starts the API server and optionally registers graceful shutdown signal handlers.
 * @param {object} runtime - Runtime dependencies such as agents and ML client.
 * @returns {Promise<{ app: object, httpServer: object, io: object, stop: Function }>} Started server bundle.
 * @throws {Error} If the server cannot bind to the configured port.
 */
async function startServer(runtime = {}) {
  try {
    const serverBundle = createServer(runtime);
    await new Promise((resolve, reject) => {
      serverBundle.httpServer.once('error', reject);
      serverBundle.httpServer.listen(config.port, resolve);
    });
    logger.info(`AEGIS API listening on http://localhost:${config.port}`);

    if (runtime.registerSignalHandlers !== false) {
      const shutdown = (signal) => {
        logger.info(`Received ${signal}; shutting down AEGIS`);
        serverBundle.stop()
          .then(() => process.exit(0))
          .catch(() => process.exit(1));
      };
      process.once('SIGINT', () => shutdown('SIGINT'));
      process.once('SIGTERM', () => shutdown('SIGTERM'));
    }

    return serverBundle;
  } catch (error) {
    logger.error('server startup failed', { error: error.message, stack: error.stack });
    throw new Error(`startServer failed: ${error.message}`);
  }
}

module.exports = {
  createServer,
  startServer
};