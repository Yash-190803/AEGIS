const fs = require('fs');
const path = require('path');
const { generateShortId } = require('../src/utils/idGenerator');

const LOG_DIR = path.resolve(process.cwd(), 'data', 'logs');
const USERS = Object.freeze(['root', 'admin', 'administrator', 'backup', 'deploy', 'user', 'test', 'oracle', 'postgres', 'ubuntu']);
const SCENARIOS = Object.freeze(['mixed', 'brute_force', 'sql_injection', 'lateral_movement', 'ransomware', 'slow_exfiltration']);

function parseArgs(argv) {
  const options = { scenario: 'mixed', count: 100, output: null };
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--scenario') options.scenario = String(argv[index + 1] || 'mixed').toLowerCase();
    if (arg === '--count') options.count = parseInt(argv[index + 1] || '100', 10);
    if (arg === '--output') options.output = argv[index + 1] || null;
  }
  if (!SCENARIOS.includes(options.scenario)) {
    throw new Error(`--scenario must be one of: ${SCENARIOS.join(', ')}`);
  }
  if (!Number.isInteger(options.count) || options.count < 1 || options.count > 5000) {
    throw new Error('--count must be an integer between 1 and 5000.');
  }
  return options;
}

function stamp(offsetSeconds = 0) {
  const date = new Date(Date.UTC(2026, 5, 20, 10, 0, offsetSeconds));
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return `${months[date.getUTCMonth()]} ${String(date.getUTCDate()).padStart(2, ' ')} ${String(date.getUTCHours()).padStart(2, '0')}:${String(date.getUTCMinutes()).padStart(2, '0')}:${String(date.getUTCSeconds()).padStart(2, '0')}`;
}

function bruteForceLine(index) {
  return `${stamp(index % 60)} webserver sshd[1234]: Failed password for ${USERS[index % USERS.length]} from 203.0.113.45 port ${52300 + index} ssh2`;
}

function sqlInjectionLine(index) {
  const payloads = ['UNION SELECT username,password FROM users--', "OR '1'='1", 'DROP TABLE sessions'];
  return `${stamp(index)} app01 nginx: 203.0.113.88 GET /search?q=${encodeURIComponent(payloads[index % payloads.length])} 500`;
}

function lateralLine(index) {
  const source = 42 + (index % 8);
  const target = 87 + (index % 12);
  const protocol = index % 3 === 0 ? 'RDP port 3389' : 'SMB port 445';
  return `${stamp(index)} ids01 netflow: 10.0.0.${source} -> 10.0.0.${target} ${protocol} workstation-to-workstation`;
}

function ransomwareLine(index) {
  if (index === 0) return `${stamp(index)} host42 process: vssadmin.exe delete shadows /all /quiet`;
  if (index === 1) return `${stamp(index)} host42 service: backup service terminated by unknown process`;
  return `${stamp(index)} fileserver fs: renamed /finance/file${index}.xlsx to /finance/file${index}.xlsx.encrypted`;
}

function exfilLine(index) {
  return `${stamp(index * 30)} dns01 network: DNS query size=${30 + (index % 20)} host=chunk${String(index).padStart(3, '0')}.data.exfil-domain.203.0.113.99.com from 10.0.0.87`;
}

function benignLine(index) {
  const hosts = ['webserver', 'app01', 'fileserver', 'db01'];
  return `${stamp(index)} ${hosts[index % hosts.length]} app: health_check status=200 requestId=${generateShortId()}`;
}

function lineForScenario(scenario, index) {
  if (scenario === 'brute_force') return bruteForceLine(index);
  if (scenario === 'sql_injection') return sqlInjectionLine(index);
  if (scenario === 'lateral_movement') return lateralLine(index);
  if (scenario === 'ransomware') return ransomwareLine(index);
  if (scenario === 'slow_exfiltration') return exfilLine(index);
  const generators = [benignLine, bruteForceLine, sqlInjectionLine, lateralLine, ransomwareLine, exfilLine];
  return generators[index % generators.length](index);
}

function generateLogs(options) {
  const lines = Array.from({ length: options.count }, (_, index) => lineForScenario(options.scenario, index));
  fs.mkdirSync(LOG_DIR, { recursive: true });
  const filePath = options.output
    ? path.resolve(process.cwd(), options.output)
    : path.join(LOG_DIR, `generated_${options.scenario}_${Date.now()}.log`);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`);
  return { filePath, count: lines.length, scenario: options.scenario };
}

function main() {
  try {
    const result = generateLogs(parseArgs(process.argv));
    console.log(`Generated ${result.count} ${result.scenario} log lines at ${result.filePath}`);
  } catch (error) {
    console.error(`generate_logs failed: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  generateLogs,
  parseArgs
};