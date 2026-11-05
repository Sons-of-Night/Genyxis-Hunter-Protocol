import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {createSocket} from 'node:dgram';
import {once} from 'node:events';
import {closeSync, openSync} from 'node:fs';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {createRadar, createServer} from '../server.mjs';

const HOST = '127.0.0.1';
const SID = 9900101;
const CONFIG = `%YAML 1.1
---
unix-command:
  enabled: no
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
`;

async function verify(signal) {
  assert.equal(process.platform, 'linux', 'Run on an authorized Kali or Ubuntu host.');
  assert.notEqual(process.getuid(), 0, 'Run Node as your regular user. Run sudo -v first.');
  const version = spawnSync('suricata', ['-V'], {encoding:'utf8', timeout:5000});
  assert.equal(version.status, 0, 'Suricata is required. Install it from your distro and check suricata -V.');
  const dir = await mkdtemp('/tmp/hunter-radar-loopback-');
  const eve = join(dir, 'eve.json');
  const config = join(dir, 'suricata.yaml');
  const rules = join(dir, 'probe.rules');
  const sensorLog = join(dir, 'suricata-output.log');
  const nonce = randomBytes(12).toString('hex');
  const signature = 'Hunter Radar loopback validation ' + nonce;
  const probe = 'GENYXIS_RADAR_PROBE_' + nonce;
  const socket = createSocket('udp4');
  const radar = createRadar({
    env:{HUNTER_RADAR_SURICATA_EVE_FILE:eve},
    // Exercise the real sensor/API pipeline without opening a Solana connection.
    webSocketFactory:() => Object.assign(new EventTarget(), {close() {}}),
    fetchImpl:async () => new Response(null, {status:503})
  });
  const server = createServer(radar);
  let sensor, sensorDone, sensorExit, passed = false;
  try {
    await writeFile(eve, '', {mode:0o600});
    socket.bind(0, HOST);
    await once(socket, 'listening', {signal});
    const port = socket.address().port;
    await writeFile(config, CONFIG, {mode:0o600});
    await writeFile(rules,
      `alert udp ${HOST} any -> ${HOST} ${port} (msg:"${signature}"; content:"${probe}"; sid:${SID}; rev:1;)\n`,
      {mode:0o600});

    server.listen(0, HOST);
    await once(server, 'listening', {signal});
    const endpoint = `http://${HOST}:${server.address().port}/api/snapshot`;
    async function snapshot() {
      const response = await fetch(endpoint, {signal:AbortSignal.any([signal, AbortSignal.timeout(2000)])});
      assert.equal(response.status, 200, 'Radar snapshot endpoint must return HTTP 200.');
      return response.json();
    }
    radar.start();
    for (let attempt = 0; attempt < 20; attempt++) {
      if ((await snapshot()).kali.ready) break;
      await delay(250, undefined, {signal});
    }
    const before = await snapshot();
    assert.equal(before.kali.ready, true, before.kali.lastError || 'Radar did not open the EVE file.');
    assert.equal(before.kali.alerts, 0, 'Expected an empty Radar sensor baseline.');

    const log = openSync(sensorLog, 'w', 0o600);
    try {
      sensor = spawn('sudo', ['-n', '--', 'timeout', '--kill-after=3s', '35s',
        'suricata', '--pcap=lo', '--runmode=single', '-k', 'none',
        '-c', config, '-S', rules, '-l', dir, '--init-errors-fatal',
        `udp and src host ${HOST} and dst host ${HOST} and dst port ${port}`
      ], {stdio:['ignore', log, log]});
      sensorDone = new Promise(resolve => {
        sensor.once('error', error => { sensorExit = error.message; resolve(); });
        sensor.once('exit', (code, exitSignal) => {
          sensorExit = exitSignal || String(code);
          resolve();
        });
      });
    } finally {
      closeSync(log);
    }

    let result;
    for (let attempt = 0; attempt < 24; attempt++) {
      if (sensorExit !== undefined) throw new Error(`Suricata exited (${sensorExit}). Check sudo -v and the sensor log.`);
      await new Promise((resolve, reject) => {
        socket.send(probe, port, HOST, error => error ? reject(error) : resolve());
      });
      await delay(1000, undefined, {signal});
      result = await snapshot();
      if (result.kali.events.some(event => event.signature === signature)) break;
    }
    const event = result.kali.events.find(item => item.signature === signature);
    assert.ok(event, 'Radar did not receive the probe alert. Check the EVE file and sensor log.');
    const raw = (await readFile(eve, 'utf8')).split('\n').slice(0, -1).map(line => JSON.parse(line));
    assert.ok(raw.some(record => record.event_type === 'alert' && record.alert?.signature_id === SID
      && record.alert.signature === signature && record.alert.action === 'allowed'
      && record.src_ip === HOST && record.dest_ip === HOST && record.dest_port === port),
    'The matching passive loopback alert must exist in the Suricata EVE log.');
    assert.equal(event.action, 'sensor-alert');
    assert.equal(event.protocol, 'UDP');
    assert.equal(result.kali.sensorReportedBlocks, 0);
    assert.equal(result.kali.rotationOrSkipCount, 0);
    assert.equal(result.counters.observed, 0);
    for (const field of ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'payload', 'packet']) {
      assert.equal(Object.hasOwn(event, field), false, `Radar exposed ${field}.`);
    }

    console.log(`PASS Hunter Radar live loopback | ${new Date().toISOString()} | SID ${SID}`);
    console.log(`${version.stdout.trim() || version.stderr.trim()} | Node ${process.version}`);
    console.log(`Suricata EVE → Radar API | sensor alerts: ${result.kali.alerts} | blocks: 0 | Solana observations: 0`);
    passed = true;
  } finally {
    sensor?.kill('SIGTERM');
    await sensorDone;
    radar.stop();
    server.close();
    socket.close();
    if (passed) {
      await rm(dir, {recursive:true, force:true});
    } else {
      console.error(`Local diagnostics: ${sensorLog} and ${eve}`);
    }
  }
}

const shutdown = new AbortController();
process.once('SIGINT', () => shutdown.abort());
process.once('SIGTERM', () => shutdown.abort());
try {
  await verify(shutdown.signal);
} catch (error) {
  console.error('FAIL Hunter Radar live loopback | ' + error.message);
  process.exitCode = 1;
}
