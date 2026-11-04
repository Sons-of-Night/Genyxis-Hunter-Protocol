/**
 * Kali-compatible, read-only local Suricata EVE JSON intrusion telemetry.
 *
 * Only actual alerts in a file produced by a locally deployed Suricata sensor are
 * displayed. This does not initiate scans, block other hosts, or attribute
 * Internet traffic to an on-chain Solana address.
 */
import {open, stat} from 'node:fs/promises';

const BATCH_BYTES = 131072;
const MAX_LINE_BYTES = 32768;
const MAX_EVENTS = 100;

export function parseSuricataAlert(line, observedAt = Date.now()) {
  let parsed;
  try { parsed = JSON.parse(line); } catch { return null; }
  if (!parsed || parsed.event_type !== 'alert' || typeof parsed.alert?.signature !== 'string') return null;
  const signature = parsed.alert.signature.trim().slice(0, 160);
  if (!signature) return null;
  const severity = Number.isInteger(parsed.alert.severity) && parsed.alert.severity >= 1 && parsed.alert.severity <= 4
    ? parsed.alert.severity : null;
  const action = String(parsed.alert.action || '').toLowerCase();
  const reportedBlocked = action === 'blocked' || action === 'drop' || action === 'reject';
  const sourceTime = Date.parse(parsed.timestamp || '');
  return {
    observedAt,
    sourceTime: Number.isFinite(sourceTime) ? sourceTime : null,
    type: 'suricata-alert',
    signature,
    classification: typeof parsed.alert.category === 'string' ? parsed.alert.category.slice(0, 100) : 'Uncategorized',
    severity,
    protocol: typeof parsed.proto === 'string' ? parsed.proto.slice(0, 12) : null,
    action: reportedBlocked ? 'sensor-reported-block' : 'sensor-alert',
    // Explicitly avoid dumping IP addresses, payloads, PCAP contents, credentials or
    // sensitive network metadata into a browser dashboard.
    source: 'Local Kali/Suricata EVE'
  };
}

export function createSuricataMonitor(file, {now = () => Date.now(), statFile = stat, openFile = open} = {}) {
  const configured = typeof file === 'string' && file.startsWith('/') && !file.includes('\0');
  let cursor = null;
  let lastError = configured ? null : 'No Suricata EVE file configured';
  let lastReadAt = null;
  let ready = false;
  let alerts = 0;
  let sensorReportedBlocks = 0;
  let rotationOrSkipCount = 0;
  let buffer = '';
  let running = false;
  let timer = null;
  const items = [];

  async function poll() {
    if (!configured || running) return;
    running = true;
    try {
      const meta = await statFile(file);
      if (!meta.isFile()) throw new Error('EVE source is not a regular file');
      if (cursor === null) {
        // Treat existing records as historical: new session counts start at ZERO.
        cursor = {ino: meta.ino, offset: meta.size};
        buffer = '';
      } else {
        if (meta.ino !== cursor.ino || meta.size < cursor.offset) {
          rotationOrSkipCount++;
          cursor = {ino:meta.ino,offset:0};buffer = '';
        }
        if (meta.size - cursor.offset > BATCH_BYTES * 8) {
          // The source grew too rapidly to safely process without unbounded lag.
          // Declare a gap and resume near the end rather than invent complete coverage.
          rotationOrSkipCount++;
          cursor.offset = Math.max(0,meta.size-BATCH_BYTES);
          buffer = '';
          const skipPartial = true;
          // The first record may be partial; an invalid JSON line is ignored.
          void skipPartial;
        }
        const length = Math.min(BATCH_BYTES,Math.max(0,meta.size-cursor.offset));
        if(length){
          const handle = await openFile(file,'r');
          let bytesRead = 0;
          const bytes = Buffer.alloc(length);
          try { ({bytesRead} = await handle.read(bytes,0,length,cursor.offset)); }
          finally { await handle.close(); }
          cursor.offset += bytesRead;
          buffer += bytes.subarray(0,bytesRead).toString('utf8');
          if(buffer.length > MAX_LINE_BYTES + BATCH_BYTES) {
            buffer = buffer.slice(-MAX_LINE_BYTES);
            rotationOrSkipCount++;
          }
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for(const line of lines) {
            if(line.length > MAX_LINE_BYTES) continue;
            const event = parseSuricataAlert(line,now());
            if(!event) continue;
            alerts++;
            if(event.action==='sensor-reported-block') sensorReportedBlocks++;
            items.push(event);
            if(items.length>MAX_EVENTS) items.shift();
          }
        }
      }
      ready = true;
      lastError = null;
      lastReadAt = now();
    } catch(error) {
      ready = false;
      lastError = String(error.message).slice(0,180);
    } finally {running = false;}
  }
  function snapshot() {
    return {
      configured,ready,lastReadAt,lastError,
      alerts,sensorReportedBlocks,rotationOrSkipCount,
      events:items.slice().reverse(),
      coverage:configured
        ? 'Only traffic visible to the local Suricata sensor; alerts are not Solana-chain threat attribution.'
        : 'No Kali/Suricata sensor connected'
    };
  }
  function start() {
    if(!configured || timer) return;
    void poll();
    timer=setInterval(()=>{void poll();},2000);
  }
  function stop() {if(timer){clearInterval(timer);timer=null;}}
  return {poll,start,stop,snapshot};
}
