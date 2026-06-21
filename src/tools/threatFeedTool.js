const fs = require('fs');
const path = require('path');

const FEED_DIR = path.resolve(process.cwd(), 'data', 'threat-feeds');
const IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_PATTERN = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
const HASH_PATTERN = /\b[a-f0-9]{64}\b/gi;
const CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/gi;

const FALLBACK_CISA = Object.freeze([
  { cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j', vulnerabilityName: 'Log4Shell', knownRansomwareCampaignUse: 'Known', severity: 'CRITICAL' },
  { cveID: 'CVE-2017-0144', vendorProject: 'Microsoft', product: 'SMBv1', vulnerabilityName: 'EternalBlue', knownRansomwareCampaignUse: 'Known', severity: 'CRITICAL' },
  { cveID: 'CVE-2023-34362', vendorProject: 'Progress', product: 'MOVEit Transfer', vulnerabilityName: 'SQL injection', knownRansomwareCampaignUse: 'Known', severity: 'CRITICAL' }
]);

const FALLBACK_OTX = Object.freeze([
  {
    pulseId: 'fallback-c2',
    pulseName: 'Cobalt Strike C2 Infrastructure',
    indicators: [
      { id: 'indicator-203-0-113-45', type: 'IPv4', indicator: '203.0.113.45', title: 'Cobalt Strike C2 Server', tags: ['CobaltStrike', 'C2', 'APT29'] }
    ]
  },
  {
    pulseId: 'fallback-ransomware',
    pulseName: 'Ransomware Staging Infrastructure',
    indicators: [
      { id: 'indicator-198-51-100-77', type: 'IPv4', indicator: '198.51.100.77', title: 'Ransomware staging host', tags: ['Ransomware', 'Exfiltration'] }
    ]
  }
]);

const FALLBACK_MITRE = Object.freeze({
  techniques: [
    { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', detection: 'Monitor authentication logs for excessive failures.' },
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', detection: 'Monitor web logs for exploit strings and abnormal errors.' },
    { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', detection: 'Monitor RDP, SMB, SSH, and WinRM lateral connections.' },
    { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', detection: 'Monitor mass file changes and shadow copy deletion.' },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', detection: 'Monitor DNS and uncommon protocol data volume.' },
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation', detection: 'Monitor sudo, UAC bypass, and SUID execution.' },
    { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion', detection: 'Monitor unusual successful logins after failures.' }
  ]
});

function readJsonFeed(fileName, fallback) {
  const filePath = path.join(FEED_DIR, fileName);
  if (!fs.existsSync(filePath)) {
    return fallback;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Failed to parse threat feed ${fileName}: ${error.message}`);
  }
}

function normalize(value) {
  return String(value || '').trim();
}

function confidenceForMatches(matches) {
  if (matches.length === 0) {
    return 0.35;
  }
  const highest = matches.some((match) => match.severity === 'CRITICAL') ? 0.93 : 0.82;
  return Math.min(0.99, Number((highest + Math.min(matches.length, 4) * 0.02).toFixed(2)));
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function memoryMatches(indicator, indicatorType, memory) {
  if (!memory) {
    return [];
  }
  const matches = [];
  if (indicatorType === 'IP' && memory.knownBadIPs && memory.knownBadIPs.has(indicator)) {
    matches.push({ indicator, source: 'SharedMemory', title: 'Known bad IP from prior intelligence', severity: memory.knownBadIPs.get(indicator).severity || 'HIGH' });
  }
  if (indicatorType === 'DOMAIN' && memory.knownBadDomains && memory.knownBadDomains.has(indicator)) {
    matches.push({ indicator, source: 'SharedMemory', title: 'Known bad domain from prior intelligence', severity: memory.knownBadDomains.get(indicator).severity || 'HIGH' });
  }
  if (indicatorType === 'FILE_HASH' && memory.knownBadHashes && memory.knownBadHashes.has(indicator)) {
    matches.push({ indicator, source: 'SharedMemory', title: 'Known malicious hash from prior intelligence', severity: memory.knownBadHashes.get(indicator).severity || 'HIGH' });
  }
  if (indicatorType === 'CVE' && memory.activeCVEs && memory.activeCVEs.has(indicator)) {
    matches.push({ indicator, source: 'SharedMemory', title: 'Active exploited CVE tracked in memory', severity: memory.activeCVEs.get(indicator).severity || 'CRITICAL' });
  }
  return matches;
}

function cisaMatches(indicator) {
  const cisa = readJsonFeed('cisa_kev.json', FALLBACK_CISA);
  return cisa
    .filter((entry) => normalize(entry.cveID).toUpperCase() === indicator.toUpperCase())
    .map((entry) => ({
      indicator,
      source: 'CISA KEV',
      title: `${entry.vendorProject} ${entry.product}: ${entry.vulnerabilityName}`,
      severity: entry.severity || 'CRITICAL',
      ransomwareUse: entry.knownRansomwareCampaignUse || 'Unknown'
    }));
}

function otxMatches(indicator) {
  const pulses = readJsonFeed('alienvault_otx.json', FALLBACK_OTX);
  return pulses.flatMap((pulse) => (pulse.indicators || [])
    .filter((item) => normalize(item.indicator).toLowerCase() === indicator.toLowerCase())
    .map((item) => ({
      indicator,
      source: 'AlienVault OTX',
      title: item.title || pulse.pulseName,
      severity: (item.tags || []).some((tag) => /apt|ransom|c2/i.test(tag)) ? 'HIGH' : 'MEDIUM',
      pulseName: pulse.pulseName,
      tags: item.tags || []
    })));
}

function inferThreatActor(matches) {
  const tags = matches.flatMap((match) => match.tags || []);
  if (tags.some((tag) => /APT29/i.test(tag))) {
    return 'APT29-like infrastructure overlap; attribution remains probabilistic';
  }
  if (tags.some((tag) => /Ransomware/i.test(tag)) || matches.some((match) => match.ransomwareUse === 'Known')) {
    return 'Pattern overlaps with active ransomware tradecraft';
  }
  if (tags.some((tag) => /CobaltStrike|C2/i.test(tag))) {
    return 'Likely commodity command-and-control tooling';
  }
  return matches.length > 0 ? 'Opportunistic scanner or shared malicious infrastructure' : null;
}

function extractArtifacts(text) {
  return {
    ips: unique(text.match(IP_PATTERN) || []),
    domains: unique(text.match(DOMAIN_PATTERN) || []),
    hashes: unique(text.match(HASH_PATTERN) || []),
    cves: unique((text.match(CVE_PATTERN) || []).map((cve) => cve.toUpperCase()))
  };
}

function keywordTechniqueScores(behavior, artifacts) {
  const corpus = `${behavior} ${(artifacts || []).join(' ')}`.toLowerCase();
  return [
    [/brute|failed password|password spray|credential/, 'T1110'],
    [/accepted password|valid account|successful login/, 'T1078'],
    [/union select|drop table|sql injection|1=1/, 'T1190'],
    [/smb|rdp|lateral|remote service|winrm|ssh pivot/, 'T1021'],
    [/encrypt|ransom|shadow copy|vssadmin/, 'T1486'],
    [/dns|exfil|canary|large transfer|tunnel/, 'T1048'],
    [/sudo|suid|uac|privilege escalation/, 'T1548']
  ].filter(([pattern]) => pattern.test(corpus)).map(([, technique]) => technique);
}

function findTechniques(ids) {
  const library = readJsonFeed('mitre_attack_techniques.json', FALLBACK_MITRE);
  const techniques = Array.isArray(library.techniques) ? library.techniques : [];
  return unique(ids).map((id) => techniques.find((technique) => technique.id === id))
    .filter(Boolean)
    .map((technique) => ({
      id: technique.id,
      name: technique.name,
      tactic: technique.tactic,
      detection: technique.detection
    }));
}

/**
 * Searches local threat intelligence feeds and SharedMemory for indicator matches.
 * @param {{ indicator: string, indicatorType: string }} args - Indicator lookup arguments.
 * @param {object} context - Optional tool execution context containing SharedMemory.
 * @returns {{ feedMatches: object[], cveIds: string[], threatActorProfile: string | null, recommendations: string[], updatedConfidence: number, confidence: number, severity: string, reasoning: string }} Lookup result.
 * @throws {Error} If the indicator request is invalid or feed parsing fails.
 */
function lookup_threat_feed(args, context = {}) {
  try {
    const indicator = normalize(args && args.indicator);
    const indicatorType = normalize(args && args.indicatorType).toUpperCase();
    if (!indicator || !['IP', 'DOMAIN', 'FILE_HASH', 'CVE', 'URL'].includes(indicatorType)) {
      throw new Error('indicator and indicatorType are required; type must be IP, DOMAIN, FILE_HASH, CVE, or URL.');
    }
    const matches = [
      ...memoryMatches(indicator, indicatorType, context.memory),
      ...(indicatorType === 'CVE' ? cisaMatches(indicator) : []),
      ...(indicatorType !== 'CVE' ? otxMatches(indicator) : [])
    ];
    if (context.memory && indicatorType === 'IP' && matches.length > 0) {
      context.memory.addKnownBadIP(indicator, 'threatFeedTool', matches.some((match) => match.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH');
    }
    const confidence = confidenceForMatches(matches);
    return {
      feedMatches: matches,
      cveIds: indicatorType === 'CVE' && matches.length > 0 ? [indicator.toUpperCase()] : [],
      threatActorProfile: inferThreatActor(matches),
      recommendations: matches.length > 0 ? ['Increase incident severity if target is business critical', 'Correlate indicator with recent authentication, DNS, and proxy logs'] : ['Continue monitoring; no local feed match found'],
      updatedConfidence: confidence,
      confidence,
      severity: matches.some((match) => match.severity === 'CRITICAL') ? 'CRITICAL' : matches.length > 0 ? 'HIGH' : 'LOW',
      reasoning: matches.length > 0 ? `${matches.length} threat intelligence match(es) found for ${indicator}.` : `No local threat intelligence match found for ${indicator}.`
    };
  } catch (error) {
    throw new Error(`lookup_threat_feed failed: ${error.message}`);
  }
}

/**
 * Maps observed attack behavior and artifacts to MITRE ATT&CK techniques.
 * @param {{ attackBehavior: string, observedArtifacts?: string[] }} args - Behavior mapping arguments.
 * @returns {{ mitreTechniques: string[], mitreTactics: string[], techniqueDetails: object[], extractedIndicators: object, recommendations: string[], confidence: number, reasoning: string }} MITRE mapping result.
 * @throws {Error} If attackBehavior is invalid or the technique library cannot be parsed.
 */
function map_to_mitre_attack(args) {
  try {
    if (!args || typeof args.attackBehavior !== 'string' || args.attackBehavior.trim().length === 0) {
      throw new Error('attackBehavior must be a non-empty string.');
    }
    const observedArtifacts = Array.isArray(args.observedArtifacts) ? args.observedArtifacts : [];
    const extractedIndicators = extractArtifacts(`${args.attackBehavior} ${observedArtifacts.join(' ')}`);
    const techniqueDetails = findTechniques(keywordTechniqueScores(args.attackBehavior, observedArtifacts));
    const mitreTechniques = techniqueDetails.map((technique) => technique.id);
    const mitreTactics = unique(techniqueDetails.map((technique) => technique.tactic));
    return {
      mitreTechniques,
      mitreTactics,
      techniqueDetails,
      extractedIndicators,
      recommendations: techniqueDetails.map((technique) => technique.detection).concat('Preserve raw evidence and correlate with endpoint telemetry.'),
      confidence: techniqueDetails.length > 0 ? Math.min(0.95, 0.68 + techniqueDetails.length * 0.07) : 0.35,
      reasoning: techniqueDetails.length > 0 ? `Mapped behavior to ${techniqueDetails.length} MITRE technique(s).` : 'No strong MITRE keyword mapping found; treat as UNKNOWN until enriched.'
    };
  } catch (error) {
    throw new Error(`map_to_mitre_attack failed: ${error.message}`);
  }
}

module.exports = {
  lookup_threat_feed,
  map_to_mitre_attack
};