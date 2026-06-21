const AGENTS = ['OrchestratorAgent', 'SentinelAgent', 'IntelFusionAgent', 'TriageAgent', 'ResponseAgent', 'ForensicsAgent', 'RedTeamAgent', 'DeceptionAgent', 'AuditAgent'];
const state = {
  socket: null,
  feedPaused: false,
  hiddenEventCount: 0,
  events: [],
  incidents: new Map(),
  hitlTimer: null,
  activeHitl: null
};

const $ = (selector) => document.querySelector(selector);
const agentGrid = $('#agentGrid');
const eventFeed = $('#eventFeed');
const incidentList = $('#incidentList');
const time = (value) => (value ? new Date(value).toLocaleTimeString() : new Date().toLocaleTimeString());
const pct = (value) => `${Math.round(Math.max(0, Math.min(1, Number(value || 0))) * 100)}%`;

function escapeText(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function iconForAgent(agentName) {
  return {
    OrchestratorAgent: 'O',
    SentinelAgent: 'S',
    IntelFusionAgent: 'I',
    TriageAgent: 'T',
    ResponseAgent: 'R',
    ForensicsAgent: 'F',
    RedTeamAgent: 'X',
    DeceptionAgent: 'D',
    AuditAgent: 'A'
  }[agentName] || '?';
}

function riskClass(score) {
  const risk = Number(score || 1);
  return risk <= 3 ? 'risk-low' : risk <= 5 ? 'risk-medium' : risk <= 7 ? 'risk-high' : 'risk-critical';
}

function statusClass(status) {
  const normalized = String(status || 'IDLE').toLowerCase();
  return normalized.includes('error') ? 'status-error' : normalized.includes('analy') ? 'status-analyzing' : normalized.includes('act') || normalized.includes('respond') ? 'status-acting' : '';
}

const metric = (id, value) => { $(id).textContent = value; };

function renderAgents(statuses = []) {
  const byName = new Map(statuses.map((status) => [status.agentName, status]));
  agentGrid.innerHTML = AGENTS.map((agentName) => {
    const status = byName.get(agentName) || { status: 'IDLE', lastAction: 'waiting', updatedAt: null };
    return `
      <div class="agent-tile" id="agent-${agentName}">
        <div class="agent-name"><span><span class="agent-icon">${iconForAgent(agentName)}</span> ${agentName.replace('Agent', '')}</span><span class="status ${statusClass(status.status)}">${escapeText(status.status)}</span></div>
        <div class="agent-action">${escapeText(status.lastAction || 'idle')}</div>
        <div class="agent-time">${escapeText(status.updatedAt ? time(status.updatedAt) : '--')}</div>
      </div>
    `;
  }).join('');
}

function renderStats(snapshot) {
  metric('#statIncidents', snapshot.systemStats.totalIncidentsToday || 0);
  metric('#statBlocked', snapshot.systemStats.totalBlockedToday || 0);
  metric('#statHitl', snapshot.systemStats.totalHITLDecisions || 0);
  metric('#statHoneypots', snapshot.activeHoneypotCount || 0);
  metric('#statAvg', `${snapshot.systemStats.avgResponseTimeMs || 0}ms`);
  metric('#statTokens', window.aegisTokenTotal || 0);
  metric('#activeIncidents', snapshot.activeIncidentCount || 0);
  metric('#blockedIps', snapshot.blockedIPCount || 0);
  metric('#uptime', uptime(snapshot.systemStats.startedAt));
  setThreatLevel(snapshot.globalThreatLevel || 'LOW');
  renderAgents(snapshot.agentStatuses || []);
}

function uptime(startedAt) {
  if (!startedAt) return '--';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000));
  const minutes = Math.floor(seconds / 60);
  return minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function setThreatLevel(level) {
  const badge = $('#threatBadge');
  const normalized = String(level || 'LOW').toLowerCase();
  badge.textContent = level;
  badge.className = `threat-badge threat-${normalized}`;
}

function badgeUpdate(selector, enabled, text) {
  const el = $(selector);
  if (text !== undefined) el.textContent = text;
  el.classList.toggle('visible', enabled);
}

function addEvent(event) {
  state.events.unshift(event);
  state.events = state.events.slice(0, 200);
  if (state.feedPaused) {
    state.hiddenEventCount += 1;
    badgeUpdate('#newEvents', true, `${state.hiddenEventCount} new events`);
  } else {
    renderFeed();
  }
  updateIncidentFromEvent(event);
}

function renderFeed() {
  eventFeed.innerHTML = state.events.map((event, index) => `
    <div class="event-entry" data-index="${index}">
      <div class="event-meta">
        <span>${escapeText(time(event.timestamp))}</span>
        <span class="pill">${escapeText(event.source)}</span>
        <span class="pill">${escapeText(event.eventType)}</span>
        <span class="pill confidence">${pct(event.confidence)}</span>
      </div>
    </div>
  `).join('');
}

function updateIncidentFromEvent(event) {
  const incident = event.data && event.data.incident ? event.data.incident : null;
  if (incident && incident.id) {
    state.incidents.set(incident.id, incident);
  }
  if (event.incidentId && state.incidents.has(event.incidentId)) {
    const current = state.incidents.get(event.incidentId);
    state.incidents.set(event.incidentId, { ...current, ...event.data });
  }
  if (event.eventType === 'HITL_REQUIRED') showHITL(event);
  if (event.eventType === 'HITL_APPROVED' || event.eventType === 'HITL_REJECTED') hideHITL(event.eventType);
  renderIncidents();
}

function renderIncidents() {
  const incidents = [...state.incidents.values()].sort((a, b) => {
    if ((a.hitlStatus === 'PENDING') !== (b.hitlStatus === 'PENDING')) return a.hitlStatus === 'PENDING' ? -1 : 1;
    return (b.riskScore || 0) - (a.riskScore || 0);
  });
  incidentList.innerHTML = incidents.map((incident) => `
    <div class="incident-card ${incident.hitlStatus === 'PENDING' ? 'hitl' : ''}" data-incident="${escapeText(incident.id)}">
      <div class="incident-title">
        <span>${escapeText(incident.type || 'UNKNOWN')}</span>
        <span class="risk ${riskClass(incident.riskScore)}">${escapeText(incident.riskScore || 1)}</span>
      </div>
      <div class="incident-details">
        ${escapeText(incident.source && incident.source.ip)} -> ${escapeText(incident.target && incident.target.hostname)}<br>
        ${escapeText(incident.status || 'DETECTING')} | ${escapeText(incident.severity || 'MEDIUM')} | ${elapsed(incident.createdAt)}
      </div>
      <div class="progress"><span style="width:${pct(incident.confidence)}"></span></div>
    </div>
  `).join('');
}

function elapsed(createdAt) {
  if (!createdAt) return 'new';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(createdAt).getTime()) / 1000));
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m`;
}

function showHITL(event) {
  const panel = $('#hitlPanel');
  state.activeHitl = event;
  panel.classList.add('visible');
  $('#hitlIncident').textContent = event.incidentId || event.data.incidentId || 'unknown incident';
  $('#hitlAction').textContent = JSON.stringify(event.data.action || event.data.proposedAction || {}, null, 2);
  $('#hitlReasoning').textContent = event.reasoning || event.data.reasoning || '';
  $('#hitlBlast').textContent = event.data.blastRadius || 'Review required before high-impact containment.';
  startCountdown(event.data.expiresAt, event.data.countdownSeconds || 300);
}

function startCountdown(expiresAt, fallbackSeconds) {
  clearInterval(state.hitlTimer);
  const end = expiresAt ? new Date(expiresAt).getTime() : Date.now() + fallbackSeconds * 1000;
  const total = Math.max(1, end - Date.now());
  state.hitlTimer = setInterval(() => {
    const remaining = Math.max(0, end - Date.now());
    const seconds = Math.ceil(remaining / 1000);
    $('#hitlCountdown').textContent = `${Math.floor(seconds / 60)} minutes ${seconds % 60} seconds remaining`;
    $('#hitlTimerFill').style.width = `${Math.round(((total - remaining) / total) * 100)}%`;
    if (remaining <= 0) clearInterval(state.hitlTimer);
  }, 1000);
}

function hideHITL(eventType) {
  clearInterval(state.hitlTimer);
  $('#hitlPanel').classList.remove('visible');
  toast(eventType === 'HITL_APPROVED' ? 'HITL decision approved' : 'HITL decision rejected');
}

const decisionBody = (decision, analyst) => (decision === 'approve' ? { approvedBy: analyst, notes: 'Approved from dashboard' } : { rejectedBy: analyst, reason: 'Rejected from dashboard' });
async function decideHITL(decision) {
  const active = state.activeHitl;
  if (!active) return;
  const analyst = $('#analystName').value.trim();
  if (!/^[a-zA-Z0-9 ]{2,80}$/.test(analyst)) {
    toast('Analyst name must use letters, numbers, and spaces');
    return;
  }
  const incidentId = active.incidentId || active.data.incidentId;
  const endpoint = `/api/hitl/${incidentId}/${decision}`;
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(decisionBody(decision, analyst))
  });
  if (!response.ok) {
    toast(`Decision failed: HTTP ${response.status}`);
    return;
  }
  hideHITL(decision === 'approve' ? 'HITL_APPROVED' : 'HITL_REJECTED');
}

function openModal(event) {
  $('#eventModalBody').textContent = JSON.stringify(event, null, 2);
  $('#eventModal').classList.add('visible');
}

function openIncident(id) {
  const incident = state.incidents.get(id);
  if (!incident) return;
  $('#incidentSidebarBody').textContent = JSON.stringify(incident, null, 2);
  $('#incidentSidebar').classList.add('visible');
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('visible');
  setTimeout(() => el.classList.remove('visible'), 3500);
}

function bindEvents() {
  $('#newEvents').addEventListener('click', () => {
    state.feedPaused = false;
    state.hiddenEventCount = 0;
    badgeUpdate('#newEvents', false);
    renderFeed();
    eventFeed.scrollTop = 0;
  });
  eventFeed.addEventListener('scroll', () => {
    state.feedPaused = eventFeed.scrollTop > 20;
  });
  eventFeed.addEventListener('click', (event) => {
    const row = event.target.closest('.event-entry');
    if (row) openModal(state.events[Number(row.dataset.index)]);
  });
  incidentList.addEventListener('click', (event) => {
    const card = event.target.closest('.incident-card');
    if (card) openIncident(card.dataset.incident);
  });
  document.querySelectorAll('[data-close]').forEach((button) => {
    button.addEventListener('click', () => $(button.dataset.close).classList.remove('visible'));
  });
  $('#approveButton').addEventListener('click', () => decideHITL('approve'));
  $('#rejectButton').addEventListener('click', () => decideHITL('reject'));
}

function connectSocket() {
  state.socket = io({ reconnection: true, reconnectionDelay: 3000 });
  state.socket.on('connect', () => {
    $('#connectionDot').classList.add('connected');
    $('#connectionText').textContent = 'connected';
  });
  state.socket.on('disconnect', () => {
    $('#connectionDot').classList.remove('connected');
    $('#connectionText').textContent = 'disconnected';
  });
  state.socket.on('aegis_event', addEvent);
  state.socket.on('system_snapshot', renderStats);
  state.socket.on('agent_heartbeat', renderAgents);
}

async function loadInitialData() {
  try {
    const [incidents, health] = await Promise.all([
      fetch('/api/incidents').then((res) => res.ok ? res.json() : []),
      fetch('/api/health').then((res) => res.ok ? res.json() : null)
    ]);
    incidents.forEach((incident) => state.incidents.set(incident.id, incident));
    if (health && health.tokenUsage) window.aegisTokenTotal = health.tokenUsage.totalTokens || 0;
    renderIncidents();
  } catch (error) {
    toast(`Initial load failed: ${error.message}`);
  }
}

function init() {
  renderAgents();
  bindEvents();
  connectSocket();
  loadInitialData();
}

document.addEventListener('DOMContentLoaded', init);
