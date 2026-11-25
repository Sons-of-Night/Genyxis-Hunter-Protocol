import test from 'node:test';
import assert from 'node:assert/strict';
import {createRadar} from '../server.mjs';

class FakeSocket extends EventTarget {
  sent = [];
  send(value) { this.sent.push(JSON.parse(value)); }
  close() {}
  emit(type, value) { this.dispatchEvent(new MessageEvent(type, {data:JSON.stringify(value)})); }
}
const signature = '5'.repeat(88);
function notification() {
  return {method:'logsNotification',params:{subscription:4,result:{
    context:{slot:30001},value:{signature,err:null,logs:[]}
  }}};
}
function fixture() {
  const socket = new FakeSocket();
  const radar = createRadar({env:{},webSocketFactory:()=>socket,
    fetchImpl:async()=>new Response(null,{status:503})});
  radar.start();
  socket.emit('open',{});
  socket.emit('message',{id:1,result:4});
  return {socket,radar};
}

test('Oversized and malformed frames are rejected without losing subsequent valid observations',()=>{
  const {socket,radar}=fixture();
  try {
    socket.emit('message',{...notification(),padding:'é'.repeat(150000)});
    socket.dispatchEvent(new MessageEvent('message',{data:'{'}));
    socket.dispatchEvent(new MessageEvent('message',{data:new Uint8Array([1,2])}));
    const rejected=radar.snapshot();
    assert.equal(rejected.rejectedMessages,3);
    assert.equal(rejected.gapCount,3);
    assert.equal(rejected.counters.observed,0);
    socket.emit('message',notification());
    assert.equal(radar.snapshot().counters.observed,1);
  } finally { radar.stop(); }
});

test('Retired sockets cannot restore subscription state or inject observations',()=>{
  const {socket,radar}=fixture();
  try {
    assert.equal(radar.snapshot().subscribed,true);
    socket.emit('close',{});
    socket.emit('open',{});
    socket.emit('message',{id:1,result:4});
    socket.emit('message',notification());
    socket.emit('error',{});
    const state=radar.snapshot();
    assert.equal(state.connected,false);
    assert.equal(state.subscribed,false);
    assert.equal(state.gapCount,1);
    assert.equal(state.counters.observed,0);
    assert.equal(socket.sent.length,1);
  } finally { radar.stop(); }
});

test('Stopped Radar ignores delayed socket callbacks',()=>{
  const {socket,radar}=fixture();
  radar.stop();
  socket.emit('open',{});
  socket.emit('message',notification());
  socket.emit('close',{});
  assert.equal(radar.snapshot().connected,false);
  assert.equal(radar.snapshot().subscribed,false);
  assert.equal(radar.snapshot().counters.observed,0);
});

test('Invalid notification payloads do not crash the feed or hide gaps',()=>{
  const {socket,radar}=fixture();
  try {
    socket.emit('message',null);
    const invalid=notification();
    invalid.params.result.value.signature='invalid';
    socket.emit('message',invalid);
    // Construct a valid JSON frame with a deeply nested provider error without
    // relying on JSON.stringify to create the deeply nested object.
    const raw=JSON.stringify(notification()).replace('"err":null','"err":'+'['.repeat(20000)+'0'+']'.repeat(20000));
    socket.dispatchEvent(new MessageEvent('message',{data:raw}));
    assert.equal(radar.snapshot().rejectedMessages,3);
    assert.equal(radar.snapshot().gapCount,3);
    assert.equal(radar.snapshot().counters.observed,0);
    socket.emit('message',notification());
    assert.equal(radar.snapshot().counters.observed,1);
  } finally {radar.stop();}
});
