import test from 'node:test';
import assert from 'node:assert/strict';
import {createRadar} from '../server.mjs';
class Socket extends EventTarget {
  sent=[];closed=0;
  send(value){this.sent.push(JSON.parse(value));}
  close(){this.closed++;}
  emit(type,value){this.dispatchEvent(new MessageEvent(type,{data:JSON.stringify(value)}));}
}
function fixture(t,watch=false){
  let time=1700000000000,slot=100;
  const socket=new Socket();
  const radar=createRadar({env:watch?{HUNTER_RADAR_WATCH_ADDRESSES:'11111111111111111111111111111111'}:{},
    now:()=>time,webSocketFactory:()=>socket,
    fetchImpl:async()=>({ok:true,json:async()=>({result:slot})})});
  t.after(()=>radar.stop());
  radar.start();
  return {radar,socket,advance:ms=>{time+=ms;},setSlot:value=>{slot=value;},open:()=>socket.emit('open',{})};
}
function observation(subscription=4){
  return {method:'logsNotification',params:{subscription,result:{context:{slot:100},
    value:{signature:'5'.repeat(88),err:null,logs:[]}}}};
}
test('Connection and subscription deadlines retire unresponsive sockets',t=>{
  const a=fixture(t);a.advance(15000);a.radar.checkFeed();
  assert.equal(a.socket.closed,1);assert.equal(a.radar.snapshot().feed.status,'disconnected');
  assert.equal(a.radar.snapshot().feed.reconnections,1);
  const b=fixture(t);b.open();b.advance(15000);b.radar.checkFeed();
  assert.equal(b.socket.closed,1);assert.match(b.radar.snapshot().lastError,/subscription timed out/);
});
test('Targeted observations cannot substitute for chain-wide freshness',t=>{
  const f=fixture(t,true);f.open();
  f.socket.emit('message',{id:1,result:4});
  f.socket.emit('message',{id:2,result:5});
  f.advance(29000);f.socket.emit('message',observation(5));
  assert.equal(f.radar.snapshot().feed.chainFresh,false);
  f.advance(1000);f.radar.checkFeed();
  assert.equal(f.socket.closed,1);
  assert.match(f.radar.snapshot().lastError,/feed stale/);
});
test('Live status requires recent chain data and advancing RPC slots',async t=>{
  const f=fixture(t);f.open();f.socket.emit('message',{id:1,result:4});
  f.socket.emit('message',observation());
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.radar.snapshot().feed.status,'degraded');
  f.setSlot(101);await f.radar.checkRpc();
  assert.equal(f.radar.snapshot().feed.status,'live');
  f.advance(30000);
  assert.equal(f.radar.snapshot().feed.status,'degraded');
  f.radar.checkFeed();
  assert.equal(f.radar.snapshot().feed.status,'disconnected');
  f.socket.emit('message',observation());
  assert.equal(f.radar.snapshot().feed.chainFresh,false);
});
test('Regressing RPC slots invalidate health and shutdown ignores late results',async t=>{
  const f=fixture(t);await new Promise(resolve=>setImmediate(resolve));
  f.setSlot(99);await f.radar.checkRpc();
  assert.equal(f.radar.snapshot().feed.rpcFresh,false);
  const socket=new Socket();let resolveFetch;
  const radar=createRadar({env:{},webSocketFactory:()=>socket,
    fetchImpl:()=>new Promise(resolve=>{resolveFetch=resolve;})});
  t.after(()=>radar.stop());
  radar.start();radar.stop();
  resolveFetch({ok:true,json:async()=>({result:999})});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(radar.snapshot().currentSlot,null);
  assert.equal(radar.snapshot().feed.status,'stopped');
});
