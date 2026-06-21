const EventEmitter = require('events');
const SharedMemory = require('./SharedMemory');
const { EVENTS } = require('../constants/events');
const { validateAgentMessage } = require('../constants/schemas');
const { generateId } = require('../utils/idGenerator');
const { createLogger } = require('../utils/logger');

const logger = createLogger('MessageBus');
let instance = null;

function buildAgentErrorMessage(agentName, eventType, error, originalMessage) {
  return {
    messageId: generateId(),
    timestamp: new Date().toISOString(),
    source: 'MessageBus',
    eventType: EVENTS.AGENT_ERROR,
    incidentId: originalMessage && originalMessage.incidentId ? originalMessage.incidentId : null,
    confidence: 1,
    data: {
      agentName,
      failedEventType: eventType,
      errorMessage: error && error.message ? error.message : String(error),
      stack: error && error.stack ? error.stack : null
    },
    reasoning: `Handler for ${agentName} failed while processing ${eventType}.`
  };
}

/**
 * Singleton event bus that validates every inter-agent message and mirrors events into SharedMemory audit state.
 */
class MessageBus extends EventEmitter {
  constructor() {
    if (instance) {
      return instance;
    }
    super();
    this.setMaxListeners(50);
    this.memory = SharedMemory.getInstance();
    instance = this;
  }

  /**
   * Returns the singleton MessageBus instance.
   * @returns {MessageBus} MessageBus instance.
   */
  static getInstance() {
    if (!instance) {
      instance = new MessageBus();
    }
    return instance;
  }

  /**
   * Emits a validated AgentMessageSchema payload to subscribers.
   * @param {string} eventType - Event constant to emit.
   * @param {object} message - AgentMessageSchema message payload.
   * @returns {boolean} True when the event was accepted and dispatched.
   */
  emit(eventType, message) {
    const validation = validateAgentMessage(message);
    if (!validation.valid) {
      logger.error(`Rejected invalid message for ${eventType}`, { errors: validation.errors, message });
      return false;
    }
    if (message.eventType !== eventType) {
      logger.error(`Rejected message with mismatched eventType for ${eventType}`, { messageEventType: message.eventType });
      return false;
    }

    logger.agent(`[${message.source}] ${eventType} | confidence: ${message.confidence}`);
    this.memory.addToAuditTrail({ type: 'BUS_EVENT', ...message });
    return super.emit(eventType, message);
  }

  /**
   * Subscribes an agent handler to a single event type with isolated error handling.
   * @param {string} eventType - Event constant to subscribe to.
   * @param {string} agentName - Name of the subscribing agent.
   * @param {Function} handler - Async or sync event handler.
   * @returns {MessageBus} This bus instance.
   * @throws {Error} If handler or agentName is invalid.
   */
  subscribe(eventType, agentName, handler) {
    if (typeof agentName !== 'string' || agentName.trim().length === 0) {
      throw new Error('subscribe requires a non-empty agentName.');
    }
    if (typeof handler !== 'function') {
      throw new Error(`subscribe requires handler to be a function for ${agentName}.`);
    }

    const wrappedHandler = async (message) => {
      try {
        await handler(message);
      } catch (error) {
        logger.error(`Handler error in ${agentName} for ${eventType}`, {
          error: error && error.message ? error.message : String(error),
          stack: error && error.stack ? error.stack : null
        });
        if (eventType !== EVENTS.AGENT_ERROR) {
          this.emit(EVENTS.AGENT_ERROR, buildAgentErrorMessage(agentName, eventType, error, message));
        }
      }
    };

    this.on(eventType, wrappedHandler);
    return this;
  }

  /**
   * Subscribes an agent handler to every standardized event type.
   * @param {string} agentName - Name of the subscribing agent.
   * @param {Function} handler - Async or sync event handler.
   * @returns {MessageBus} This bus instance.
   */
  subscribeToAll(agentName, handler) {
    for (const eventType of Object.values(EVENTS)) {
      this.subscribe(eventType, agentName, handler);
    }
    return this;
  }
}

module.exports = MessageBus;