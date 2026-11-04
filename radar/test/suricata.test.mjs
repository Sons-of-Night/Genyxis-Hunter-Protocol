import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,appendFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createSuricataMonitor,parseSuricataAlert} from '../kali/suricata.mjs';

test('Suricata EVE parser only accepts real alert records and limits exposed fields',()=>{
  const line=JSON.stringify({
    timestamp:'2026-11-03T21:00:00.000Z',event_type:'alert',
    src_ip:'10.0.0.4',dest_ip:'10.0.0.5',
    payload:'PRIVATE_PAYLOAD',
    proto:'TCP',alert:{signature:'Attempted suspicious access',severity:2,category:'Attempted Access',action:'allowed'}
  });
  const parsed=parseSuricataAlert(line,10000);
  assert.equal(parsed.signature,'Attempted suspicious access');
  assert.equal(parsed.action,'sensor-alert');
  assert.equal(parsed.severity,2);
  assert.equal(parsed.protocol,'TCP');
  assert.equal(parsed.observedAt,10000);
  assert.equal(JSON.stringify(parsed).includes('PRIVATE_PAYLOAD'),false);
  assert.equal(JSON.stringify(parsed).includes('10.0.0.4'),false);
  assert.equal(parseSuricataAlert('not json'),null);
  assert.equal(parseSuricataAlert(JSON.stringify({event_type:'flow'})),null);
  assert.equal(parseSuricataAlert(JSON.stringify({event_type:'alert',alert:{signature:'drop',action:'blocked'}})).action,'sensor-reported-block');
});

test('Monitor reads only new local log records and labels sensor-reported blocks accurately',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'hunter-radar-suricata-'));
  const file=join(dir,'eve.json');
  const line=(signature,action)=>JSON.stringify({event_type:'alert',alert:{signature,action,severity:1},proto:'TCP'})+'\n';
  try {
    await writeFile(file,line('Historical alert','allowed'));
    const sensor=createSuricataMonitor(file,{now:()=>1234});
    await sensor.poll(); // start at EOF; no historical claim of live alert
    assert.equal(sensor.snapshot().alerts,0);
    await appendFile(file,line('Observed IDS alert','allowed'));
    await sensor.poll();
    assert.equal(sensor.snapshot().alerts,1);
    assert.equal(sensor.snapshot().sensorReportedBlocks,0);
    await appendFile(file,line('Sensor did block this','blocked'));
    await sensor.poll();
    const state=sensor.snapshot();
    assert.equal(state.alerts,2);
    assert.equal(state.sensorReportedBlocks,1);
    assert.equal(state.events[0].action,'sensor-reported-block');
    assert.equal(state.events[1].signature,'Observed IDS alert');
    assert.equal(state.ready,true);
    sensor.stop();
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('Unconfigured sensor does not invent activity',async()=>{
  const sensor=createSuricataMonitor('');
  await sensor.poll();
  const state=sensor.snapshot();
  assert.equal(state.configured,false);
  assert.equal(state.ready,false);
  assert.equal(state.alerts,0);
  assert.deepEqual(state.events,[]);
});
