const OpenAI = require('openai');
const config = require('../config/env');
const { withRetry } = require('../utils/retry');
const { generateId } = require('../utils/idGenerator');
const { createLogger } = require('../utils/logger');

const logger = createLogger('OpenAIClient');

const MOCK_RESPONSES = Object.freeze({
  analyze_log_batch: {
    detectedEvents: [{
      type: 'BRUTE_FORCE',
      sourceIP: '203.0.113.45',
      targetService: 'ssh',
      confidence: 0.87,
      evidence: ['150 failed auth attempts followed by one successful login'],
      suggestedMitreTechnique: 'T1110'
    }],
    overallAssessment: 'Active brute force attack detected against SSH with successful credential compromise.',
    recommendsEscalation: true,
    confidence: 0.87
  },
  lookup_threat_feed: {
    feedMatches: [{ indicator: '203.0.113.45', source: 'AlienVault OTX', title: 'Known C2 Server', severity: 'HIGH' }],
    cveIds: [],
    threatActorProfile: 'Opportunistic scanner using automated credential attacks',
    recommendations: ['Block the source IP', 'Review the compromised backup account'],
    updatedConfidence: 0.91,
    confidence: 0.91
  },
  calculate_risk_score: {
    riskScore: 7,
    severity: 'HIGH',
    confidence: 0.87,
    reasoning: 'Active brute force from known bad IP against SSH service with likely account compromise.'
  },
  determine_response_level: {
    responseLevel: 3,
    requiresHITL: false,
    confidence: 0.87,
    reasoning: 'Risk score 7 and confidence above 0.75 make automated IP blocking appropriate.'
  },
  execute_alert_only: {
    actionTaken: 'ALERT_ONLY',
    actionId: 'mock-alert-action',
    rollbackToken: null,
    success: true,
    reasoning: 'Analyst notification was emitted without system state changes.',
    blastRadius: 'No operational impact.',
    confidence: 1
  },
  execute_block_ip: {
    success: true,
    actionId: 'mock-action-uuid',
    rollbackToken: 'mock-rollback-token',
    blastRadius: 'Single IP blocked, no collateral impact',
    reasoning: 'Mock perimeter firewall state was updated for the suspicious source IP.',
    confidence: 1
  },
  collect_evidence: {
    evidenceBundle: ['150 failed auth log lines collected', '1 successful auth log line collected'],
    confidence: 0.86
  },
  simulate_attack_scenario: {
    scenario: 'BRUTE_FORCE',
    steps: ['Reconnaissance: port scan', 'Credential attack: SSH brute force', 'Initial access: weak password'],
    logArtifacts: ['Jun 20 10:23:01 webserver sshd: Failed password for root from 203.0.113.45 port 52301 ssh2'],
    confidence: 0.9
  },
  deploy_honeypot: {
    honeypotId: 'mock-honeypot-uuid',
    assetType: 'FAKE_SSH_SERVER',
    status: 'DEPLOYED',
    confidence: 0.95
  }
});

function resolveOpenAIConstructor() {
  return OpenAI && OpenAI.default ? OpenAI.default : OpenAI;
}

function firstToolName(tools) {
  if (!Array.isArray(tools) || tools.length === 0 || !tools[0].function) {
    return 'default';
  }
  return tools[0].function.name || 'default';
}

function approximateTokens(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value || '');
  return Math.max(1, Math.ceil(text.length / 4));
}

function buildMockPayload(toolName) {
  return MOCK_RESPONSES[toolName] || {
    summary: 'Mock reasoning completed without a specialized tool response.',
    confidence: 0.72,
    reasoning: `No specialized mock response registered for ${toolName}.`
  };
}

function buildMockChatCompletion(options) {
  const toolName = firstToolName(options.tools);
  const payload = buildMockPayload(toolName);
  const content = JSON.stringify(payload);
  const promptTokens = approximateTokens(options.messages);
  const completionTokens = approximateTokens(content);
  return {
    id: `chatcmpl-mock-${generateId()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: options.model || config.openaiModelPrimary,
    choices: [{
      index: 0,
      message: { role: 'assistant', content },
      finish_reason: 'stop'
    }],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens
    }
  };
}

function buildMockEmbedding(text) {
  const source = String(text || '');
  const vector = [];
  for (let index = 0; index < 128; index += 1) {
    const charCode = source.charCodeAt(index % Math.max(source.length, 1)) || 0;
    vector.push(Number((((charCode + index) % 101) / 100).toFixed(4)));
  }
  return vector;
}

/**
 * Retry-aware OpenAI SDK wrapper with deterministic mock mode and cumulative token accounting.
 */
class OpenAIClient {
  /**
   * Creates an OpenAI client using validated application config.
   */
  constructor() {
    this.totalInputTokens = 0;
    this.totalOutputTokens = 0;
    this.totalTokens = 0;
    this.client = null;

    if (!config.mockMode) {
      const OpenAIConstructor = resolveOpenAIConstructor();
      this.client = new OpenAIConstructor({ apiKey: config.openAiApiKey });
    }
  }

  /**
   * Calls chat.completions.create with retry logic and token accounting.
   * @param {object} options - OpenAI chat completion options.
   * @returns {Promise<object>} Raw OpenAI chat completion response.
   * @throws {Error} If the request fails after retries or options are invalid.
   */
  async chatCompletion(options) {
    try {
      if (!options || !Array.isArray(options.messages)) {
        throw new Error('chatCompletion requires options.messages array.');
      }
      const requestOptions = { model: config.openaiModelPrimary, ...options };
      const response = config.mockMode
        ? buildMockChatCompletion(requestOptions)
        : await withRetry(
          () => this.client.chat.completions.create(requestOptions),
          {
            maxRetries: config.maxOpenAIRetries,
            baseDelayMs: config.openaiRetryBaseDelayMs,
            onRetry: (error, attemptNumber) => {
              logger.warn('Retrying OpenAI chat completion', { attemptNumber, error: error.message });
            }
          }
        );

      this.recordUsage(response.usage);
      return response;
    } catch (error) {
      logger.error('OpenAI chat completion failed', { error: error.message, stack: error.stack });
      throw new Error(`OpenAI chat completion failed: ${error.message}`);
    }
  }

  /**
   * Creates an embedding vector for text with retry logic.
   * @param {string} text - Text to embed.
   * @returns {Promise<number[]>} Embedding vector.
   * @throws {Error} If embedding generation fails.
   */
  async getEmbedding(text) {
    try {
      if (typeof text !== 'string' || text.length === 0) {
        throw new Error('getEmbedding requires non-empty text.');
      }
      if (config.mockMode) {
        return buildMockEmbedding(text);
      }
      const response = await withRetry(
        () => this.client.embeddings.create({ model: 'text-embedding-3-small', input: text }),
        {
          maxRetries: config.maxOpenAIRetries,
          baseDelayMs: config.openaiRetryBaseDelayMs,
          onRetry: (error, attemptNumber) => {
            logger.warn('Retrying OpenAI embedding request', { attemptNumber, error: error.message });
          }
        }
      );
      this.recordUsage(response.usage);
      return response.data[0].embedding;
    } catch (error) {
      logger.error('OpenAI embedding failed', { error: error.message, stack: error.stack });
      throw new Error(`OpenAI embedding failed: ${error.message}`);
    }
  }

  /**
   * Returns cumulative usage and estimated GPT-4o cost.
   * @returns {{ totalInputTokens: number, totalOutputTokens: number, totalTokens: number, estimatedCostUSD: number }} Usage stats.
   */
  getUsageStats() {
    const inputCost = (this.totalInputTokens / 1000000) * 5;
    const outputCost = (this.totalOutputTokens / 1000000) * 15;
    return {
      totalInputTokens: this.totalInputTokens,
      totalOutputTokens: this.totalOutputTokens,
      totalTokens: this.totalTokens,
      estimatedCostUSD: Number((inputCost + outputCost).toFixed(6))
    };
  }

  /**
   * Records token usage from an OpenAI response.
   * @param {object | undefined} usage - OpenAI usage object.
   * @returns {void}
   */
  recordUsage(usage) {
    const inputTokens = usage && usage.prompt_tokens ? usage.prompt_tokens : 0;
    const outputTokens = usage && usage.completion_tokens ? usage.completion_tokens : 0;
    const totalTokens = usage && usage.total_tokens ? usage.total_tokens : inputTokens + outputTokens;
    this.totalInputTokens += inputTokens;
    this.totalOutputTokens += outputTokens;
    this.totalTokens += totalTokens;
  }
}

module.exports = OpenAIClient;
