#!/usr/bin/env node
/**
 * Hunter Radar: live, read-only Solana MAINNET security observations.
 * No simulated activity, private keys, chain mutations, or interference with Genyxis.
 * Requires Node.js >=22 for built-in WebSocket.
 */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createSuricataMonitor } from './kali/suricata.mjs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const SIGNATURE = /^[1-9A-HJ-NP-Za-km-z]{64,100}$/;
const HISTORY_LIMIT = 500;
const MAX_WATCH = 12;
const MAX_ASSESS_BYTES = 4096;
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1)(?::([1-9][0-9]{0,4}))?$/i;

// Reject DNS-rebinding hosts and cross-site browser requests even on loopback.
// This is a boundary guard, not a substitute for authentication of local clients.
function trustedLocalRequest(req) {
  const host = req.headers.host;
  if (typeof host !== 'string') return false;
  const match = LOCAL_HOST.exec(host);
  if (!match || (match[1] && Number(match[1]) !== req.socket.localPort)) return false;
  const origin = req.headers.origin;
  if (origin !== undefined && origin !== 'http://' + host.toLowerCase()) return false;
  const site = req.headers['sec-fetch-site'];
  return site === undefined || site === 'same-origin' || site === 'none';
}

function addresses(text, max = 64) {
  const items = String(text || '').split(',').map(s => s.trim()).filter(Boolean);
  if (items.length > max || items.some(a => !ADDRESS.test(a))) {
    throw new Error('Invalid Solana address list or limit exceeded');
  }
  return [...new Set(items)];
}
function checkedEndpoint(raw, kind) {
  const url = new URL(raw);
  const allowed = kind === 'ws' ? ['wss:', 'ws:'] : ['https:', 'http:'];
  if (!allowed.includes(url.protocol) || url.username || url.password) throw new Error('Invalid RPC endpoint');
  if ((url.protocol === 'http:' || url.protocol === 'ws:') && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
    throw new Error('Non-local RPC connections require TLS');
  }
  return url.toString();
}
export function assessPolicy(programIds, accounts, denySet) {
  if (!Array.isArray(programIds) || !Array.isArray(accounts) || programIds.length > 64 || accounts.length > 64
    || [...programIds, ...accounts].some(s => typeof s !== 'string' || !ADDRESS.test(s))) {
    throw new Error('Provide programIds and accounts as arrays of at most 64 Solana public keys each');
  }
  const matches = [...new Set([...programIds, ...accounts].filter(a => denySet.has(a)))];
  return {
    decision: matches.length ? 'deny' : 'no_match',
    matchedAddresses: matches,
    basis: matches.length ? 'Operator-configured denylist matched' : 'No configured denylist match',
    limitation: 'Policy-only check; does not simulate a transaction, validate ownership, prove safety, or block the Solana network.',
    appliesOnlyIfIntegrated: true
  };
}
export function normalizeObservation(notification, watchedAddress, denySet, now = Date.now()) {
  const result = notification?.params?.result;
  const value = result?.value;
  if (!value || !SIGNATURE.test(value.signature || '') || !Array.isArray(value.logs)) return null;
  const invoked = [...new Set(value.logs.map(s => {
    const match = /^Program ([1-9A-HJ-NP-Za-km-z]{32,44}) invoke \[/.exec(String(s));
    return match?.[1] || null;
  }).filter(Boolean))];
  const matches = invoked.filter(program => denySet.has(program));
  const failed = value.err !== null && value.err !== undefined;
  return {
    signature: value.signature,
    slot: Number.isSafeInteger(result?.context?.slot) ? result.context.slot : null,
    time: now, outcome: failed ? 'failed' : 'succeeded',
    programs: invoked.slice(0, 16), watchedAddresses: watchedAddress ? [watchedAddress] : [],
    policyMatches: matches, 
    error: failed ? JSON.stringify(value.err).slice(0, 160) : null,
    // A failed transaction or denylist match is NOT proof of malicious intent.
    finding: matches.length ? 'Configured policy match' : (failed ? 'Transaction failure' : 'Observed transaction')
  };
}
export function buckets(events, now, minutes = 15) {
  const list = Array.from({length: minutes}, (_, i) => ({
    minute: i - minutes + 1, observed: 0, failed: 0, policy: 0
  }));
  for (const e of events) {
    const offset = Math.floor((now - e.time) / 60000);
    if (offset < 0 || offset >= minutes) continue;
    const bucket = list[minutes - 1 - offset];
    bucket.observed++;
    if (e.outcome === 'failed') bucket.failed++;
    if (e.policyMatches.length) bucket.policy++;
  }
  return list;
}
export function createRadar({
  env = process.env,
  now = () => Date.now(),
  webSocketFactory = url => new WebSocket(url),
  fetchImpl = fetch
} = {}) {
  const httpUrl = checkedEndpoint(env.HUNTER_RADAR_RPC_HTTP || 'https://api.mainnet.solana.com', 'http');
  const wsUrl = checkedEndpoint(env.HUNTER_RADAR_RPC_WS || httpUrl.replace(/^http/, 'ws'), 'ws');
  const watch = addresses(env.HUNTER_RADAR_WATCH_ADDRESSES, MAX_WATCH);
  const deny = new Set(addresses(env.HUNTER_RADAR_DENY_ADDRESSES));
  const rpcHost = new URL(httpUrl).hostname;
  const kaliSensor = createSuricataMonitor(env.HUNTER_RADAR_SURICATA_EVE_FILE,{now});
  let ws = null, stopped = false, connected = false, subscribed = false, lastEventAt = null;
  let rpcOk = false, currentSlot = null, lastRpcAt = null, rpcError = null;
  let lastError = null, reconnections = 0, gapCount = 0, reconnectTimer = null;
  let refreshTimer = null, totalObserved = 0, totalFailed = 0, totalPolicyMatches = 0;
  let totalWatchObserved = 0, checks = 0, denyRecommendations = 0, seq = 0;
  const events = new Map(), pending = new Map(), subscriptions = new Map();

  function record(observation) {
    const old = events.get(observation.signature);
    if (old) {
      // A watch subscription may arrive after the chain-wide one.
      for (const address of observation.watchedAddresses) {
        if (!old.watchedAddresses.includes(address)) {
          old.watchedAddresses.push(address);
          if (old.watchedAddresses.length === 1) totalWatchObserved++;
        }
      }
      return;
    }
    events.set(observation.signature, observation);
    totalObserved++;
    if (observation.outcome === 'failed') totalFailed++;
    if (observation.policyMatches.length) totalPolicyMatches++;
    if (observation.watchedAddresses.length) totalWatchObserved++;
    if (events.size > HISTORY_LIMIT) events.delete(events.keys().next().value);
  }
  function sendSubscription(filter, watchAddress = null) {
    const id = ++seq;
    pending.set(id, watchAddress);
    ws.send(JSON.stringify({
      jsonrpc: '2.0', id, method: 'logsSubscribe',
      params: [filter, {commitment: 'confirmed'}]
    }));
  }
  function connect() {
    if (stopped) return;
    pending.clear(); subscriptions.clear(); subscribed = false; connected = false;
    try {
      ws = webSocketFactory(wsUrl);
      ws.addEventListener('open', () => {
        connected = true; lastError = null;
        sendSubscription('all'); // Mainnet-wide non-vote transaction logs, subject to provider limits.
        for (const address of watch) sendSubscription({mentions:[address]}, address);
      });
      ws.addEventListener('message', event => {
        let message;
        try { message = JSON.parse(typeof event.data === 'string' ? event.data : String(event.data)); }
        catch { return; }
        if (Number.isInteger(message.id) && pending.has(message.id)) {
          if (message.error) {
            lastError = 'Subscription rejected: ' + String(message.error.message || 'RPC error').slice(0, 130);
          } else if (Number.isInteger(message.result)) {
            subscriptions.set(message.result, pending.get(message.id));
            if (pending.get(message.id) === null) subscribed = true;
          }
          pending.delete(message.id);
          return;
        }
        if (message.method !== 'logsNotification') return;
        const address = subscriptions.get(message.params?.subscription);
        // Ignore notifications outside our acknowledged subscriptions.
        if (address === undefined) return;
        const observed = normalizeObservation(message, address, deny, now());
        if (observed) {
          lastEventAt = now();
          record(observed);
        }
      });
      ws.addEventListener('error', () => { lastError = 'WebSocket connection error'; });
      ws.addEventListener('close', () => {
        if (stopped) return;
        if (connected) gapCount++; // explicitly disclose gaps instead of claiming comprehensive coverage
        connected = false; subscribed = false; reconnect();
      });
    } catch(error) { lastError = String(error.message).slice(0,140); reconnect(); }
  }
  function reconnect() {
    if (stopped || reconnectTimer) return;
    reconnections++;
    reconnectTimer = setTimeout(() => {reconnectTimer = null; connect();}, Math.min(30000, 1000 * (2 ** Math.min(reconnections, 5))));
  }
  async function checkRpc() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);
    try {
      const response = await fetchImpl(httpUrl, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({jsonrpc:'2.0',id:1,method:'getSlot',params:[{commitment:'confirmed'}]}),
        signal:controller.signal
      });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const body = await response.json();
      if (!Number.isSafeInteger(body.result)) throw new Error(body.error?.message || 'Bad getSlot response');
      currentSlot = body.result; rpcOk = true; rpcError = null; lastRpcAt = now();
    } catch(e) { rpcOk = false; rpcError = String(e.message).slice(0,140); lastRpcAt = now(); }
    finally { clearTimeout(timeout); }
  }
  function assess(payload) {
    const result = assessPolicy(payload?.programIds, payload?.accounts, deny);
    checks++;
    if (result.decision === 'deny') denyRecommendations++;
    return result;
  }
  function snapshot() {
    const time = now(), recent = [...events.values()].reverse();
    return {
      product:'Hunter Radar', chain:'Solana', cluster:'mainnet-beta', mode:'REAL MAINNET — READ ONLY',
      sourceHost:rpcHost, connected, subscribed, rpcOk, currentSlot, lastRpcAt,
      lastEventAt, lastError, rpcError, gapCount,
      completeness:'Best-effort live feed. Provider throttling, disconnects and retention limits may omit transactions.',
      scope:'All non-vote transaction logs received from selected mainnet RPC since process start; only configured policy matches are flagged.',
      watchCount:watch.length, watchAddresses:watch, denylistSize:deny.size,
      sessionStartedAt:startedAt, kali:kaliSensor.snapshot(), counters:{
        observed:totalObserved, failed:totalFailed, policyMatches:totalPolicyMatches,
        watchObserved:totalWatchObserved, policyChecks:checks, denyRecommendations
      },
      buckets:buckets(recent, time), events:recent.slice(0,100)
    };
  }
  const startedAt = now();
  function start() {
    kaliSensor.start();
    connect(); void checkRpc();
    refreshTimer = setInterval(() => { void checkRpc(); },25000);
  }
  function stop() {
    kaliSensor.stop();
    stopped = true; connected=false; subscribed=false;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (refreshTimer) clearInterval(refreshTimer);
    if (ws) ws.close();
  }
  return {start,stop,snapshot,assess,checkRpc};
}
export function createServer(radar) {
  const files = {'/':'index.html','/index.html':'index.html','/app.js':'app.js','/styles.css':'styles.css'};
  const server = http.createServer(async (req,res) => {
    const security = {
      'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff',
      'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
      'Cross-Origin-Resource-Policy':'same-origin',
      'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    };
    for (const [k,v] of Object.entries(security)) res.setHeader(k,v);
    if (!trustedLocalRequest(req)) {
      res.writeHead(403); res.end('Local origin required'); return;
    }
    const url = new URL(req.url,'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/api/snapshot' || url.pathname === '/api/health')) {
      res.writeHead(200,{'Content-Type':'application/json; charset=utf-8'});
      res.end(JSON.stringify(radar.snapshot())); return;
    }
    if (req.method === 'POST' && url.pathname === '/api/assess') {
      if (!/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(req.headers['content-type'] || '')) {
        res.writeHead(415); res.end('Expected application/json'); return;
      }
      if (Number(req.headers['content-length'] || 0) > MAX_ASSESS_BYTES) {
        res.writeHead(413); res.end('Request too large'); return;
      }
      let chunks = [], bytes = 0, rejected = false;
      try {
        for await (const chunk of req) {
          bytes += chunk.length;
          if (bytes > MAX_ASSESS_BYTES) { rejected = true; chunks = []; }
          else if (!rejected) chunks.push(chunk);
        }
      } catch {
        if (!res.destroyed) { res.writeHead(400); res.end('Invalid request body'); }
        return;
      }
      if (rejected) { res.writeHead(413); res.end('Request too large'); return; }
      const data = Buffer.concat(chunks).toString('utf8');
      try {
        const result = radar.assess(JSON.parse(data));
        res.writeHead(200,{'Content-Type':'application/json; charset=utf-8'});
        res.end(JSON.stringify(result));
      } catch(error) {
        res.writeHead(400,{'Content-Type':'application/json; charset=utf-8'});
        res.end(JSON.stringify({error:String(error.message).slice(0,180)}));
      }
      return;
    }
    if (req.method !== 'GET') {res.writeHead(405);res.end('Method not allowed');return;}
    const name = files[url.pathname];
    if (!name) {res.writeHead(404);res.end('Not found');return;}
    try {
      const body = await readFile(join(HERE,'public',name));
      const mime = name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html';
      res.writeHead(200,{'Content-Type':mime+'; charset=utf-8'});res.end(body);
    } catch {res.writeHead(500);res.end('Dashboard asset missing');}
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 50;
  return server;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const radar = createRadar();
  const port = Number(process.env.HUNTER_RADAR_PORT || '4190');
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid HUNTER_RADAR_PORT');
  const server = createServer(radar);
  server.listen(port,'127.0.0.1',()=>console.log('Hunter Radar listening at http://127.0.0.1:'+port+' — Solana mainnet, real observations only'));
  radar.start();
  const shutdown=()=>{radar.stop();server.close();};
  process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
}
