import test from 'node:test';
import assert from 'node:assert/strict';
import {request as httpRequest} from 'node:http';
import {assessPolicy, normalizeObservation, buckets, createRadar, createServer} from '../server.mjs';

const A='11111111111111111111111111111111';
const B='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const SIG='5'.repeat(88);

function notification(sub=4, err=null) {
  return {method:'logsNotification',params:{
    subscription:sub,
    result:{context:{slot:30001},value:{
      signature:SIG,err,
      logs:['Program '+A+' invoke [1]','Program '+A+' success']
    }}
  }};
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
});
test('History buckets contain only provided events',()=>{
  const now=1700000000000;
  const e=normalizeObservation(notification(),null,new Set(),now);
  const chart=buckets([e],now);
  assert.equal(chart.length,15);
  assert.equal(chart.at(-1).observed,1);
  assert.equal(chart.reduce((n,x)=>n+x.observed,0),1);
});
test('Real input pipeline deduplicates mainnet stream and targeted-watch events',async()=>{
  let socket;
  class FakeSocket{
    constructor(){this.handlers={};this.sent=[];socket=this;}
    addEventListener(type,handler){(this.handlers[type]??=[]).push(handler);}
    emit(type,data){for(const h of this.handlers[type]||[])h({data:JSON.stringify(data)});}
    send(value){this.sent.push(JSON.parse(value));}
    close(){/* no messages after shutdown */}
  }
  const radar=createRadar({
    env:{HUNTER_RADAR_RPC_HTTP:'https://api.mainnet.solana.com',HUNTER_RADAR_WATCH_ADDRESSES:A,HUNTER_RADAR_DENY_ADDRESSES:B},
    webSocketFactory:()=>new FakeSocket(),
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

test('Radar HTTP boundary rejects rebinding, cross-site access and invalid JSON requests', async () => {
  const radar = {snapshot: () => ({status:'local'}), assess: () => ({decision:'no_match'})};
  const server = createServer(radar);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  function requestStatus({path='/api/snapshot', method='GET', headers={}, body}={}) {
    return new Promise((resolve, reject) => {
      const request = httpRequest({hostname:'127.0.0.1', port, path, method, headers}, response => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
        response.on('error', reject);
      });
      request.on('error', reject);
      request.end(body);
    });
  }
  try {
    assert.equal(await requestStatus(), 200);
    assert.equal(await requestStatus({headers:{Host:'localhost:'+port}}), 200);
    assert.equal(await requestStatus({headers:{Host:'attacker.example:'+port}}), 403);
    assert.equal(await requestStatus({headers:{Host:'127.0.0.1:1'}}), 403);
    assert.equal(await requestStatus({headers:{Origin:'http://attacker.example'}}), 403);
    assert.equal(await requestStatus({headers:{'Sec-Fetch-Site':'cross-site'}}), 403);
    const body = JSON.stringify({programIds:[],accounts:[]});
    assert.equal(await requestStatus({
      path:'/api/assess', method:'POST', body, headers:{'Content-Type':'application/json'}
    }), 200);
    assert.equal(await requestStatus({
      path:'/api/assess', method:'POST', body, headers:{'Content-Type':'text/plain'}
    }), 415);
    assert.equal(await requestStatus({
      path:'/api/assess', method:'POST', body:'x'.repeat(4097),
      headers:{'Content-Type':'application/json'}
    }), 413);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
