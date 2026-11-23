import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {request} from 'node:http';
import {connect} from 'node:net';
import {assessPolicy, normalizeObservation, createRadar, createServer} from '../server.mjs';

const A='11111111111111111111111111111111';
const B='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const SIG='5'.repeat(88);

function notification(sub=4, err=null, signature=SIG) {
  return {method:'logsNotification',params:{
    subscription:sub,
    result:{context:{slot:30001},value:{
      signature,err,
      logs:['Program '+A+' invoke [1]','Program '+A+' success']
    }}
  }};
}

class FakeSocket extends EventTarget {
  sent = [];
  emit(type, data) { this.dispatchEvent(new MessageEvent(type, {data:JSON.stringify(data)})); }
  send(value) { this.sent.push(JSON.parse(value)); }
  close() {}
}

test('Policy assessment only denies actual configured matches and never claims simulation',()=>{
  const deny=new Set([A]);
  assert.equal(assessPolicy([A],[],deny).decision,'deny');
  assert.equal(assessPolicy([B],[],deny).decision,'no_match');
  assert.equal(assessPolicy([B],[],deny).appliesOnlyIfIntegrated,true);
  assert.throws(()=>assessPolicy(['not-an-address'],[],deny));
  assert.throws(()=>assessPolicy(Array(65).fill(A),[],deny));
});
test('Logs are classified as observations rather than assumed threats',()=>{
  const observed=normalizeObservation(notification(),null,new Set(),1000);
  assert.equal(observed.signature,SIG);
  assert.equal(observed.slot,30001);
  assert.equal(observed.outcome,'succeeded');
  assert.equal(observed.policyMatches.length,0);
  assert.equal(observed.finding,'Observed transaction');
  const failure=normalizeObservation(notification(4,{InstructionError:[0,'Custom']}),A,new Set(),1000);
  assert.equal(failure.outcome,'failed');
  assert.deepEqual(failure.watchedAddresses,[A]);
  assert.equal(failure.finding,'Transaction failure');
  const match=normalizeObservation(notification(),null,new Set([A]),1000);
  assert.deepEqual(match.policyMatches,[A]);
  assert.equal(match.finding,'Configured policy match');
  assert.equal(normalizeObservation({params:{result:{value:{signature:'bad',logs:[]}}}},null,new Set()),null);
  assert.equal(normalizeObservation(notification(4,null,[SIG]),null,new Set()),null);
});
test('Timeline retains counts and deduplicates watch notifications after event details expire',()=>{
  let time = 60_000 * 28_333_333;
  const socket = new FakeSocket();
  const radar = createRadar({
    env:{HUNTER_RADAR_WATCH_ADDRESSES:A,HUNTER_RADAR_DENY_ADDRESSES:A},
    webSocketFactory:()=>socket,
    fetchImpl:async()=>new Response(null,{status:503}),
    now:()=>time
  });
  radar.start();
  try {
    socket.emit('open');
    socket.emit('message',{id:1,result:4});
    socket.emit('message',{id:2,result:5});
    socket.emit('message',notification());
    time += 60_000;
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    for (let i = 0; i < 600; i++) {
      const signature = '6'.repeat(86) + alphabet[Math.floor(i / alphabet.length)] + alphabet[i % alphabet.length];
      socket.emit('message',notification(4, i % 2 ? null : 'AccountNotFound', signature));
    }
    assert.deepEqual(radar.snapshot().buckets.slice(-2),[
      {minute:-1,observed:1,failed:0,policy:1},
      {minute:0,observed:600,failed:300,policy:600}
    ]);
    socket.emit('message',notification(5));
    socket.emit('message',notification(5));

    const state = radar.snapshot();
    assert.equal(state.events.length,100);
    assert.ok(!state.events.some(event=>event.signature===SIG));
    assert.equal(state.counters.observed,601);
    assert.equal(state.counters.watchObserved,1);
    assert.equal(state.buckets.length,15);
    assert.equal(state.buckets.at(-1).observed,600);
    time += 14 * 60_000;
    assert.equal(radar.snapshot().buckets[0].observed,600);
    time += 60_000;
    assert.ok(radar.snapshot().buckets.every(bucket=>bucket.observed===0));
    socket.emit('message',notification(4,null,'7'.repeat(88)));
    assert.deepEqual(radar.snapshot().buckets.at(-1),{minute:0,observed:1,failed:0,policy:1});
  } finally { radar.stop(); }
});
test('Real input pipeline deduplicates mainnet stream and targeted-watch events',async()=>{
  const socket = new FakeSocket();
  const radar=createRadar({
    env:{HUNTER_RADAR_RPC_HTTP:'https://api.mainnet.solana.com',HUNTER_RADAR_WATCH_ADDRESSES:A,HUNTER_RADAR_DENY_ADDRESSES:B},
    webSocketFactory:()=>socket,
    fetchImpl:async()=>({ok:true,json:async()=>({result:35000})}),
    now:()=>1700000000000
  });
  radar.start();
  try{
    socket.emit('open',{});
    assert.equal(socket.sent.length,2);
    assert.equal(socket.sent[0].params[0],'all');
    assert.deepEqual(socket.sent[1].params[0],{mentions:[A]});
    socket.emit('message',{id:1,result:4});
    socket.emit('message',{id:2,result:5});
    socket.emit('message',null);
    socket.emit('message',notification(4));
    socket.emit('message',notification(5));
    const state=radar.snapshot();
    assert.equal(state.connected,true);
    assert.equal(state.subscribed,true);
    assert.equal(state.counters.observed,1);
    assert.equal(state.counters.watchObserved,1);
    assert.equal(state.events[0].watchedAddresses[0],A);
    assert.equal(state.counters.policyMatches,0);
    const denied=radar.assess({programIds:[B],accounts:[]});
    assert.equal(denied.decision,'deny');
    assert.equal(radar.snapshot().counters.denyRecommendations,1);
    const server=createServer(radar);
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    try {
      const base='http://127.0.0.1:'+server.address().port;
      const response=await fetch(base+'/api/snapshot');
      assert.equal(response.status,200);
      assert.equal((await response.json()).cluster,'mainnet-beta');
      const attempt=await fetch(base+'/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({programIds:[B],accounts:[]})});
      assert.equal((await attempt.json()).decision,'deny');
      assert.equal((await fetch(base+'/missing')).status,404);
    } finally {await new Promise(resolve=>server.close(resolve));}
  }finally{radar.stop();}
});

test('Policy API survives an interrupted upload and handles its full supported body size', {timeout:5000}, async()=>{
  const radar = createRadar({env:{HUNTER_RADAR_DENY_ADDRESSES:B}});
  const server = createServer(radar);
  server.listen(0,'127.0.0.1');
  await once(server,'listening');
  const {port} = server.address();
  const endpoint = `http://127.0.0.1:${port}/api/assess`;
  const client = connect(port,'127.0.0.1');
  try {
    await once(client,'connect');
    const incoming = once(server,'request');
    client.write(`POST /api/assess HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Length: 100\r\n\r\n{`);
    const [req] = await incoming;
    const aborted = once(req,'aborted');
    client.destroy();
    await aborted;

    const post = body=>fetch(endpoint,{method:'POST',body});
    assert.equal((await post('{')).status,400);
    // This is fewer than 8192 characters, but more than 8192 UTF-8 bytes.
    assert.equal((await post(JSON.stringify('é'.repeat(4096)))).status,413);
    const valid = JSON.stringify({programIds:Array(64).fill(B),accounts:Array(64).fill(B)});
    const response = await post(valid.padEnd(8192));
    assert.equal(response.status,200);
    assert.equal((await response.json()).decision,'deny');
    assert.equal(radar.snapshot().counters.policyChecks,1);
    assert.equal((await fetch(`http://127.0.0.1:${port}/api/health`)).status,200);
  } finally {
    client.destroy();
    await new Promise(resolve=>server.close(resolve));
  }
});

test('Loopback API rejects a non-local Host and survives an invalid request target',async()=>{
  const server = createServer(createRadar({env:{}}));
  server.listen(0,'127.0.0.1');
  await once(server,'listening');
  const {port} = server.address();
  const status = (path,host)=>new Promise((resolve,reject)=>{
    const req = request({hostname:'127.0.0.1',port,path,headers:{host}},res=>{
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error',reject);
    req.end();
  });
  try {
    assert.equal(await status('/api/snapshot',`rebound.invalid:${port}`),403);
    assert.equal(await status('http://[',`127.0.0.1:${port}`),400);
    assert.equal(await status('/api/snapshot',`localhost:${port}`),200);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});
