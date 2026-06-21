function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function normalizeScore(score) {
  if (typeof score !== 'number' || !Number.isFinite(score)) {
    throw new Error(`Confidence score must be a finite number. Received: ${score}`);
  }
  return clamp(score, 0, 1);
}

/**
 * Combines multiple confidence signals into a single score using a simplified Dempster-Shafer-inspired method.
 * @param {number[]} scores - Confidence scores from 0 to 1.
 * @returns {number} Combined confidence capped at 0.99.
 * @throws {Error} If scores is not an array or contains invalid values.
 */
function combineConfidences(scores) {
  if (!Array.isArray(scores)) {
    throw new Error('combineConfidences requires an array of scores.');
  }
  if (scores.length === 0) {
    return 0;
  }
  const normalized = scores.map(normalizeScore);
  if (normalized.length === 1) {
    return normalized[0];
  }

  const combined = normalized.slice(1).reduce((current, next) => {
    const agreementReward = current * next * 0.1;
    return clamp(((current + next) / 2) + agreementReward, 0, 0.99);
  }, normalized[0]);

  return Number(combined.toFixed(4));
}

/**
 * Adjusts LLM confidence based on ML pre-score alignment.
 * @param {number} llmConfidence - LLM confidence score from 0 to 1.
 * @param {number | null} mlScore - ML anomaly score from 0 to 1, or null if unavailable.
 * @param {string | null} mlRecommendation - ML recommendation enum.
 * @returns {number} Adjusted confidence capped at 0.99.
 * @throws {Error} If llmConfidence or mlScore is invalid.
 */
function adjustForMLAlignment(llmConfidence, mlScore, mlRecommendation) {
  const baseConfidence = normalizeScore(llmConfidence);
  if (mlScore === null || mlScore === undefined || mlRecommendation === null || mlRecommendation === undefined) {
    return baseConfidence;
  }
  const normalizedMlScore = normalizeScore(mlScore);

  if (mlRecommendation === 'DISCARD' && baseConfidence >= 0.5) {
    return Number(clamp(baseConfidence - 0.2, 0, 0.99).toFixed(4));
  }
  if (['ESCALATE_TO_LLM', 'MONITOR'].includes(mlRecommendation) && normalizedMlScore >= 0.4 && baseConfidence >= 0.5) {
    return Number(clamp(baseConfidence + 0.1, 0, 0.99).toFixed(4));
  }
  if (mlRecommendation === 'DISCARD' && baseConfidence < 0.5) {
    return Number(clamp(baseConfidence + 0.05, 0, 0.99).toFixed(4));
  }

  return baseConfidence;
}

/**
 * Converts a raw Isolation Forest anomaly score to a normalized 0-1 anomaly confidence.
 * @param {number} rawScore - Raw Isolation Forest score, typically between -1 and 0.
 * @returns {number} Normalized anomaly score from 0 to 1.
 * @throws {Error} If rawScore is not a finite number.
 */
function normalizeIsolationForestScore(rawScore) {
  if (typeof rawScore !== 'number' || !Number.isFinite(rawScore)) {
    throw new Error(`Isolation Forest score must be a finite number. Received: ${rawScore}`);
  }
  return Number(clamp(rawScore * -2, 0, 1).toFixed(4));
}

module.exports = {
  combineConfidences,
  adjustForMLAlignment,
  normalizeIsolationForestScore
};