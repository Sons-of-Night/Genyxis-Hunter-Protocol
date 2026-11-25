import test from 'node:test';
import assert from 'node:assert/strict';
import {performance, monitorEventLoopDelay} from 'node:perf_hooks';
import {setImmediate as yieldLoop} from 'node:timers/promises';
import {createRadar, MAX_WS_MESSAGE_BYTES} from '../server.mjs';

const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function signature(i) {
  let suffix='';
  do {suffix=alphabet[i%58]+suffix;i=Math.floor(i/58);} while(i);
  return '5'.repeat(83)+suffix.padStart(5,'1');
}
function notification(i,bytes) {
  const body=JSON.stringify({method:'logsNotification',params:{subscription:4,result:{
    context:{slot:30001},value:{signature:signature(i),err:null,logs:['Program 11111111111111111111111111111111 invoke [1]']}
  }},padding:''});
  const missing=bytes-Buffer.byteLength(body);
  assert.ok(missing>=0);
  return body.slice(0,-2)+'é'.repeat(Math.floor(missing/2))+'x'.repeat(missing%2)+'"}';
}
class FakeSocket extends EventTarget {
  send() {}
  close() {}
  frame(data) {this.dispatchEvent(new MessageEvent('message',{data}));}
}
function fixture() {
  const socket=new FakeSocket();
  const radar=createRadar({env:{},webSocketFactory:()=>socket,fetchImpl:async()=>new Response(null,{status:503})});
  radar.start();
  socket.dispatchEvent(new Event('open'));
  socket.frame(JSON.stringify({id:1,result:4}));
  return {socket,radar};
}

test('UTF-8 byte histogram includes exact boundary and rejects one byte over',()=>{
  const {socket,radar}=fixture();
  try {
    const before=radar.snapshot().messageSizes;
    const lengths=[1024,1025,4096,4097,16384,16385,65536,65537,131072,131073,MAX_WS_MESSAGE_BYTES,MAX_WS_MESSAGE_BYTES+1];
    for(const [i,bytes] of lengths.entries()){
      const frame=notification(i,bytes);
      assert.equal(Buffer.byteLength(frame),bytes);
      socket.frame(frame);
    }
    socket.frame(new Uint8Array([1,2]));
    const state=radar.snapshot(),m=state.messageSizes;
    assert.equal(m.limitBytes,262144);
    assert.equal(m.textMessages-before.textMessages,lengths.length);
    assert.equal(m.textBytes-before.textBytes,lengths.reduce((a,b)=>a+b,0));
    assert.equal(m.maxTextBytes,MAX_WS_MESSAGE_BYTES+1);
    assert.equal(m.oversizedMessages,1);
    assert.equal(m.nonTextMessages,1);
    assert.deepEqual(m.counts.map((n,i)=>n-before.counts[i]),[1,2,2,2,2,2,1]);
    assert.equal(state.counters.observed,lengths.length-1);
    assert.equal(state.rejectedMessages,2);
    assert.equal(state.gapCount,2);
    m.counts.fill(0);
    assert.equal(radar.snapshot().messageSizes.counts.at(-1),1);
  } finally {radar.stop();}
});

test('Synthetic mixed-size ingest benchmark: 12000 unique observations without silent loss',{timeout:60000},async t=>{
  const {socket,radar}=fixture();
  const count=12000,durations=[];
  const delay=monitorEventLoopDelay({resolution:10});
  const before=radar.snapshot().messageSizes;
  const cpuStart=process.cpuUsage(),rssStart=process.memoryUsage().rss;
  let rssSampleMax=rssStart,bytesTotal=0;
  delay.enable();
  try {
    await yieldLoop();
    const start=performance.now();
    for(let i=0;i<count;i++){
      const bytes=i%100===0?MAX_WS_MESSAGE_BYTES:i%10===0?65536:i%3===0?8192:1024;
      const frame=notification(i,bytes);
      bytesTotal+=bytes;
      const ts=performance.now();
      socket.frame(frame);
      durations.push(performance.now()-ts);
      if(i%100===99){
        rssSampleMax=Math.max(rssSampleMax,process.memoryUsage().rss);
        await yieldLoop();
      }
    }
    const elapsedMs=performance.now()-start;
    const state=radar.snapshot(),m=state.messageSizes;
    assert.equal(state.counters.observed,count);
    assert.equal(state.rejectedMessages,0);
    assert.equal(state.gapCount,0);
    assert.equal(m.textMessages-before.textMessages,count);
    assert.equal(m.textBytes-before.textBytes,bytesTotal);
    assert.equal(m.maxTextBytes,MAX_WS_MESSAGE_BYTES);
    assert.equal(m.oversizedMessages,0);
    assert.equal(state.events.length,100);
    durations.sort((a,b)=>a-b);
    const percentile=p=>durations[Math.ceil(count*p)-1];
    const cpu=process.cpuUsage(cpuStart);
    t.diagnostic('HUNTXR_CAPACITY '+JSON.stringify({
      fixture:'in-process synthetic messages, not live network throughput',node:process.version,platform:process.platform,arch:process.arch,
      count,bytesTotal,elapsedMs,messagesPerSecond:count/(elapsedMs/1000),
      handlerP95Ms:percentile(.95),handlerP99Ms:percentile(.99),cpuUserMs:cpu.user/1000,cpuSystemMs:cpu.system/1000,
      rssStartBytes:rssStart,rssSampleMaxBytes:rssSampleMax,eventLoopP99Ms:delay.count?delay.percentile(99)/1e6:null,
      rejectedMessages:state.rejectedMessages,gapCount:state.gapCount
    }));
  } finally {delay.disable();radar.stop();}
});
