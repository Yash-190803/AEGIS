const config = require('../config/env');
const SharedMemory = require('./SharedMemory');
const MessageBus = require('./MessageBus');
const OpenAIClient = require('./OpenAIClient');
const ToolRegistry = require('./ToolRegistry');
const { generateId } = require('../utils/idGenerator');
const { createLogger } = require('../utils/logger');
const { EVENTS } = require('../constants/events');
const { isConfidenceScore, isPlainObject } = require('../constants/schemas');

function safeStringify(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (error) {
    return JSON.stringify({ serializationError: error.message });
  }
}

function extractMessage(response) {
  return response && response.choices && response.choices[0] ? response.choices[0].message : {};
}

function extractJsonCandidate(text) {
  const source = String(text || '').trim();
  const start = source.search(/[\[{]/);
  if (start === -1) {
    return null;
  }
  const opener = source[start];
  const closer = opener === '{' ? '}' : ']';
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < source.length; index += 1) {
    const char = source[index];
    if (escaped) {
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else if (char === '"') {
      inString = !inString;
    } else if (!inString && char === opener) {
      depth += 1;
    } else if (!inString && char === closer) {
      depth -= 1;
      if (depth === 0) {
        return source.slice(start, index + 1);
      }
    }
  }
  return null;
}

function parseJsonResponse(text) {
  try {
    return JSON.parse(text);
  } catch (initialError) {
    const candidate = extractJsonCandidate(text);
    if (!candidate) {
      return { error: 'Invalid JSON response', rawResponse: text, parseError: initialError.message };
    }
    try {
      return JSON.parse(candidate);
    } catch (candidateError) {
      return { error: 'Invalid JSON response', rawResponse: text, parseError: candidateError.message };
    }
  }
}

function buildCompletionOptions(messages, tools) {
  const options = { model: config.openaiModelPrimary, messages };
  if (Array.isArray(tools) && tools.length > 0) {
    options.tools = tools;
    options.tool_choice = 'auto';
  }
  return options;
}

/**
 * Abstract base class for all AEGIS agents, providing lifecycle, reasoning, tool execution, and bus emission helpers.
 */
class AgentBase {
  /**
   * Creates a new agent base instance.
   * @param {string} agentName - Unique agent name.
   * @param {string} systemPrompt - System prompt used for model reasoning.
   * @param {object[]} tools - OpenAI tool definitions available to this agent.
   * @throws {Error} If required constructor values are invalid.
   */
  constructor(agentName, systemPrompt, tools = []) {
    if (typeof agentName !== 'string' || agentName.trim().length === 0) {
      throw new Error('AgentBase requires a non-empty agentName.');
    }
    if (typeof systemPrompt !== 'string' || systemPrompt.trim().length === 0) {
      throw new Error(`AgentBase requires a non-empty systemPrompt for ${agentName}.`);
    }
    this.name = agentName;
    this.systemPrompt = systemPrompt;
    this.tools = tools;
    this.openai = new OpenAIClient();
    this.memory = SharedMemory.getInstance();
    this.bus = MessageBus.getInstance();
    this.logger = createLogger(agentName);
    this.isRunning = false;
    this.conversationHistory = [];
  }

  /**
   * Runs the model reasoning loop, including up to five rounds of tool calls.
   * @param {string} userPrompt - Agent task prompt.
   * @param {object} additionalContext - Extra structured context for the reasoning call.
   * @returns {Promise<object>} Parsed JSON model response or an error object for invalid JSON.
   * @throws {Error} If the OpenAI call or tool execution fails.
   */
  async think(userPrompt, additionalContext = {}) {
    try {
      this.memory.log(this.name, 'THINK_START', { userPrompt, additionalContext });
      const snapshot = this.memory.getSystemSnapshot();
      const contextInjection = [
        'AEGIS shared context:',
        safeStringify({ snapshot, additionalContext })
      ].join('\n');
      const messages = [
        { role: 'system', content: this.systemPrompt },
        { role: 'user', content: `${contextInjection}\n\n${userPrompt}` }
      ];

      let response = await this.openai.chatCompletion(buildCompletionOptions(messages, this.tools));
      let message = extractMessage(response);
      let rounds = 0;

      while (Array.isArray(message.tool_calls) && message.tool_calls.length > 0 && rounds < 5) {
        messages.push(message);
        for (const toolCall of message.tool_calls) {
          const functionName = toolCall.function ? toolCall.function.name : '';
          const rawArgs = toolCall.function ? toolCall.function.arguments : '{}';
          const toolResult = await this.executeTool(functionName, rawArgs);
          messages.push({ role: 'tool', tool_call_id: toolCall.id, content: toolResult });
        }
        rounds += 1;
        response = await this.openai.chatCompletion(buildCompletionOptions(messages, this.tools));
        message = extractMessage(response);
      }

      if (Array.isArray(message.tool_calls) && message.tool_calls.length > 0) {
        throw new Error(`Tool loop exceeded maximum rounds for ${this.name}.`);
      }

      const usage = response.usage || {};
      this.logger.info('tokens', {
        input: usage.prompt_tokens || 0,
        output: usage.completion_tokens || 0,
        total: usage.total_tokens || 0
      });
      const parsed = parseJsonResponse(message.content || '');
      this.conversationHistory.push({ userPrompt, response: parsed, timestamp: new Date().toISOString() });
      this.memory.log(this.name, 'THINK_COMPLETE', { parsed });
      return parsed;
    } catch (error) {
      this.memory.log(this.name, 'THINK_ERROR', { error: error.message });
      this.logger.error('think failed', { error: error.message, stack: error.stack });
      throw new Error(`${this.name} think failed: ${error.message}`);
    }
  }

  /**
   * Executes a registered tool and returns the serialized result for an OpenAI tool message.
   * @param {string} toolName - Registered tool function name.
   * @param {object | string} toolArgs - Tool arguments object or JSON string.
   * @returns {Promise<string>} Serialized tool result.
   * @throws {Error} If the tool is missing, args are invalid, or execution fails.
   */
  async executeTool(toolName, toolArgs) {
    try {
      const parsedArgs = typeof toolArgs === 'string' ? JSON.parse(toolArgs || '{}') : toolArgs;
      this.memory.log(this.name, 'TOOL_EXECUTION_START', { toolName, toolArgs: parsedArgs });
      const handler = this.resolveToolHandler(toolName);
      const result = await handler(parsedArgs, { agentName: this.name, memory: this.memory, bus: this.bus });
      const serialized = typeof result === 'string' ? result : JSON.stringify(result);
      this.memory.log(this.name, 'TOOL_EXECUTION_COMPLETE', { toolName, result });
      return serialized;
    } catch (error) {
      this.memory.log(this.name, 'TOOL_EXECUTION_ERROR', { toolName, error: error.message });
      this.logger.error('tool execution failed', { toolName, error: error.message, stack: error.stack });
      throw new Error(`${this.name} failed to execute tool ${toolName}: ${error.message}`);
    }
  }

  /**
   * Finds a callable tool handler from ToolRegistry.
   * @param {string} toolName - Tool function name.
   * @returns {Function} Tool handler.
   * @throws {Error} If no handler is available.
   */
  resolveToolHandler(toolName) {
    if (typeof ToolRegistry.executeTool === 'function') {
      return (args, context) => ToolRegistry.executeTool(toolName, args, context);
    }
    const handlers = ToolRegistry.TOOL_HANDLERS || ToolRegistry.toolHandlers || {};
    const handler = handlers[toolName] || ToolRegistry[toolName];
    if (typeof handler !== 'function') {
      throw new Error(`No registered handler found for tool: ${toolName}`);
    }
    return handler;
  }

  /**
   * Emits a standardized AgentMessageSchema message.
   * @param {string} eventType - Event constant.
   * @param {object} data - Event payload.
   * @param {string | null} incidentId - Related incident ID.
   * @param {number} confidence - Confidence score from 0 to 1.
   * @returns {boolean} True when the bus accepted the message.
   * @throws {Error} If confidence or data is invalid.
   */
  emit(eventType, data, incidentId = null, confidence = 1.0) {
    if (!isConfidenceScore(confidence)) {
      throw new Error(`Invalid confidence for ${this.name} emit: ${confidence}`);
    }
    if (!isPlainObject(data)) {
      throw new Error(`${this.name} emit data must be an object.`);
    }
    const message = {
      messageId: generateId(),
      timestamp: new Date().toISOString(),
      source: this.name,
      eventType,
      incidentId,
      confidence,
      data,
      reasoning: typeof data.reasoning === 'string' ? data.reasoning : `${this.name} emitted ${eventType}.`
    };
    this.memory.updateAgentStatus(this.name, 'ACTIVE', `emitted ${eventType}`);
    return this.bus.emit(eventType, message);
  }

  /**
   * Subscribes this agent to a bus event.
   * @param {string} eventType - Event constant.
   * @param {Function} handler - Handler method.
   * @returns {MessageBus} MessageBus instance.
   */
  subscribe(eventType, handler) {
    return this.bus.subscribe(eventType, this.name, handler.bind(this));
  }

  /**
   * Starts this agent and emits AGENT_STARTED.
   * @returns {Promise<void>}
   * @throws {Error} If startup fails.
   */
  async start() {
    try {
      this.isRunning = true;
      this.memory.updateAgentStatus(this.name, 'IDLE', 'starting');
      this.emit(EVENTS.AGENT_STARTED, { agentName: this.name, reasoning: `${this.name} started successfully.` }, null, 1);
    } catch (error) {
      this.isRunning = false;
      this.logger.error('agent start failed', { error: error.message, stack: error.stack });
      throw new Error(`${this.name} failed to start: ${error.message}`);
    }
  }

  /**
   * Stops this agent and updates SharedMemory status.
   * @returns {void}
   */
  stop() {
    this.isRunning = false;
    this.memory.updateAgentStatus(this.name, 'STOPPED', 'stopped');
  }
}

module.exports = AgentBase;