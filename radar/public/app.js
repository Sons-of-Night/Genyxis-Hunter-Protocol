'use strict';
const byId = id => document.getElementById(id);
const formatter = new Intl.NumberFormat('en-US');
let latest = null, paused = false, currentPage = 'overview', viewingFindings = false;
let angle = 0, canvasSize = {w:1,h:1};
const canvas = byId('defenseCanvas');
const ctx = canvas.getContext('2d');

function text(id, value) { const e=byId(id); if(e) e.textContent=String(value); }
function timeAgo(time) {
  if (!time) return 'No events received';
  const s = Math.max(0,Math.round((Date.now()-time)/1000));
  return s < 60 ? s + 's ago' : Math.round(s/60)+'m ago';
}
function short(s) {return s ? s.slice(0,7)+'…'+s.slice(-6) : 'Unknown';}
function eventLabel(e) {return e.policyMatches.length ? 'Configured policy match' : (e.outcome==='failed' ? 'Failed Solana transaction' : 'Solana transaction observed');}
function domEvent(e) {
  const row=document.createElement('article');row.className='feed-item';
  const mark=document.createElement('div');
  mark.className='feed-symbol'+(e.policyMatches.length?' policy':e.outcome==='failed'?' failed':'');
  mark.textContent=e.policyMatches.length?'!':e.outcome==='failed'?'×':'✓';
  const main=document.createElement('div'), title=document.createElement('b');
  title.textContent=eventLabel(e);
  const link=document.createElement('a');
  link.textContent=short(e.signature);
  link.href='https://explorer.solana.com/tx/'+encodeURIComponent(e.signature)+'?cluster=mainnet-beta';
  link.target='_blank';link.rel='noopener noreferrer';
  const context=document.createElement('small');
  context.append('Slot '+(e.slot??'unknown')+' · ',link);
  if (e.watchedAddresses.length) context.append(' · WATCHED');
  if (e.policyMatches.length) context.append(' · '+e.policyMatches.length+' DENYLIST MATCH'+(e.policyMatches.length===1?'':'ES'));
  main.append(title,context);
  const timestamp=document.createElement('time');
  timestamp.dateTime=new Date(e.time).toISOString();
  timestamp.textContent=new Date(e.time).toLocaleTimeString();
  row.append(mark,main,timestamp);
  return row;
}
function renderList(target,events,empty) {
  const list=byId(target);list.replaceChildren();
  if(!events.length){const node=document.createElement('div');node.className='empty';node.textContent=empty;list.append(node);return;}
  const fragment=document.createDocumentFragment();
  for(const e of events) fragment.append(domEvent(e));
  list.append(fragment);
}
function renderChart(data) {
  const chart=byId('trend');
  chart.replaceChildren();
  const svgNS='http://www.w3.org/2000/svg';
  function elem(tag,attrs={},content=null) {
    const n=document.createElementNS(svgNS,tag);
    for(const [k,v] of Object.entries(attrs)) n.setAttribute(k,String(v));
    if(content!==null)n.textContent=content;
    chart.append(n);return n;
  }
  const max=Math.max(1,...data.flatMap(x=>[x.observed,x.failed,x.policy]));
  for(let i=0;i<=4;i++){
    const y=22+i*28;
    elem('line',{x1:30,y1:y,x2:675,y2:y,class:'axis'});
    elem('text',{x:0,y:y+4},String(Math.round(max*(1-i/4))));
  }
  if(data.every(d=>!d.observed)){elem('text',{x:286,y:82},'No observed events yet');return;}
  const points=key=>data.map((item,i)=>{
    const x=35+(i/(data.length-1))*630;
    const y=134-(item[key]/max)*112;
    return x.toFixed(1)+','+y.toFixed(1);
  }).join(' ');
  elem('polyline',{points:points('observed'),class:'line-observed'});
  elem('polyline',{points:points('failed'),class:'line-failed'});
  elem('polyline',{points:points('policy'),class:'line-policy'});
  elem('text',{x:35,y:157},'15 minutes ago');
  elem('text',{x:615,y:157},'Now');
}

function renderKali(snapshot){
  const kali=snapshot.kali||{configured:false,ready:false,alerts:0,sensorReportedBlocks:0,rotationOrSkipCount:0,events:[]};
  text('mKaliAlerts',formatter.format(kali.alerts));
  text('kaliAlertCount',formatter.format(kali.alerts));
  text('kaliBlockCount',formatter.format(kali.sensorReportedBlocks));
  text('kaliGaps',formatter.format(kali.rotationOrSkipCount));
  text('sKali',!kali.configured?'Not configured':kali.ready?'Receiving file':'Log unavailable');
  text('kaliBadge',!kali.configured?'UNCONFIGURED':kali.ready?'LOCAL SENSOR CONNECTED':'SENSOR OFFLINE');
  const feed=byId('kaliFeed');
  feed.replaceChildren();
  if(!kali.events.length){
    const empty=document.createElement('div');
    empty.className='empty';
    empty.textContent=!kali.configured?'No local Kali Suricata sensor configured.':kali.ready?'No new Suricata alert events have been received.':'Kali sensor data is unavailable.';
    feed.append(empty);
  } else {
    for(const event of kali.events){
      const line=document.createElement('article');line.className='feed-item';
      const marker=document.createElement('span');
      marker.className='feed-symbol'+(event.action==='sensor-reported-block'?' policy':' failed');
      marker.textContent=event.action==='sensor-reported-block'?'■':'!';
      const body=document.createElement('div');
      const title=document.createElement('b');title.textContent=event.signature;
      const details=document.createElement('small');
      details.textContent=(event.action==='sensor-reported-block'?'SENSOR-REPORTED BLOCK':'IDS ALERT')+
        ' · Severity '+(event.severity??'?')+' · '+event.classification+
        (event.protocol?' · '+event.protocol:'');
      body.append(title,details);
      const time=document.createElement('time');
      time.textContent=new Date(event.observedAt).toLocaleTimeString();
      line.append(marker,body,time);feed.append(line);
    }
  }
}

function render(snapshot) {
  const connected=snapshot.connected && snapshot.subscribed;
  const status=byId('liveStatus');
  status.textContent=connected?'LIVE FEED':snapshot.connected?'SUBSCRIBING':'DISCONNECTED';
  status.className='status '+(connected?'':snapshot.connected?'muted':'bad');
  byId('sideDot').className='dot '+(connected?'on':'off');
  text('sideState',connected?'MAINNET FEED CONNECTED':'MAINNET FEED NOT READY');
  text('rpcStatus',snapshot.rpcOk?'RPC • SLOT '+formatter.format(snapshot.currentSlot):'RPC unavailable');
  text('lastReceived',timeAgo(snapshot.lastEventAt));
  renderKali(snapshot);
  text('mObserved',formatter.format(snapshot.counters.observed));
  text('mFailed',formatter.format(snapshot.counters.failed));
  text('mWatched',formatter.format(snapshot.counters.watchObserved));
  text('mMatches',formatter.format(snapshot.counters.policyMatches));
  text('mDenied',formatter.format(snapshot.counters.denyRecommendations));
  text('sStream',connected?'Connected':'Not connected');
  text('sWatch',snapshot.watchCount ? snapshot.watchCount+' address'+(snapshot.watchCount===1?'':'es') : 'Unconfigured');
  text('sPolicy',snapshot.denylistSize ? snapshot.denylistSize+' entry'+(snapshot.denylistSize===1?'':'ies') : 'Unconfigured');
  text('sAssessment','Local API active');
  text('sceneBadge',connected?'LIVE MAINNET':snapshot.connected?'SUBSCRIBING':'NO LIVE FEED');
  text('feedCount',snapshot.events.length+' recent');
  text('coverage','Session started '+new Date(snapshot.sessionStartedAt).toLocaleTimeString()+' • Disconnection gaps: '+snapshot.gapCount);
  const warnings=[];
  if(!connected) warnings.push('Live mainnet feed is not yet connected. No protection or full coverage can be claimed.');
  if(snapshot.lastError)warnings.push(snapshot.lastError);
  if(snapshot.rpcError)warnings.push('RPC health: '+snapshot.rpcError);
  if(snapshot.gapCount)warnings.push(snapshot.gapCount+' connection interruption(s) since startup; missing transactions were not recovered.');
  if(snapshot.denylistSize===0)warnings.push('No denylist is configured. Policy-match detections are disabled.');
  if(snapshot.kali?.configured && !snapshot.kali.ready)warnings.push('Kali sensor: '+(snapshot.kali.lastError||'Log unavailable'));
  const warning=byId('warning');
  warning.hidden=warnings.length===0;
  warning.textContent=warnings.join(' • ');
  renderList('overviewFeed',snapshot.events.slice(0,7),'Waiting for genuine Solana mainnet events…');
  renderList('fullFeed',(viewingFindings ? snapshot.events.filter(e=>e.policyMatches.length):snapshot.events),
    viewingFindings?'No configured policy matches received.':'Waiting for genuine Solana mainnet events…');
  renderChart(snapshot.buckets);
  text('watchCount',snapshot.watchCount+' configured');
  const wl=byId('watchedAddresses');wl.replaceChildren();
  if(!snapshot.watchAddresses.length) {
    const div=document.createElement('div');div.className='empty';div.textContent='No monitored public addresses configured.';wl.append(div);
  }else{
    for(const address of snapshot.watchAddresses){
      const row=document.createElement('div');row.className='watch-row';row.textContent=address;wl.append(row);
    }
  }
}
function selectPage(page){
  currentPage=page;
  for(const tab of document.querySelectorAll('.nav'))tab.classList.toggle('active',tab.dataset.page===page);
  for(const section of document.querySelectorAll('.page'))section.classList.toggle('visible',section.id==='page-'+page);
  const title={overview:'Overview',activity:'Live Activity',watchlist:'Watchlist',kali:'Kali Sensors',policy:'Policy Check',about:'Coverage & Limits'};
  byId('pageTitle').replaceChildren(document.createTextNode('Hunter Radar '));
  const s=document.createElement('span');s.textContent=title[page];byId('pageTitle').append(s);
}
for(const tab of document.querySelectorAll('.nav'))tab.addEventListener('click',()=>selectPage(tab.dataset.page));
byId('filterFindings').addEventListener('change',e=>{viewingFindings=e.target.checked;if(latest)renderList('fullFeed', viewingFindings?latest.events.filter(x=>x.policyMatches.length):latest.events,'No matching observations received.');});
byId('pauseButton').addEventListener('click',()=>{paused=!paused;text('pauseButton',paused?'Resume view':'Pause view');if(!paused&&latest)render(latest);});
byId('policyForm').addEventListener('submit',async event=>{
  event.preventDefault();
  const parse=id=>byId(id).value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);
  const result=byId('assessmentResult');result.textContent='Performing actual configured-policy assessment…';
  try{
    const response=await fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({programIds:parse('programIds'),accounts:parse('accountIds')})});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||'Policy API request failed');
    result.textContent='Decision: '+data.decision.toUpperCase()+'\n'+data.basis+'\nMatched addresses: '+(data.matchedAddresses.join(', ')||'none')+'\n\n'+data.limitation;
  }catch(error){result.textContent='Assessment failed: '+error.message;}
});
async function refresh(){
  try {
    const response=await fetch('/api/snapshot',{cache:'no-store'});
    if(!response.ok)throw new Error('HTTP '+response.status);
    latest=await response.json();
    if(!paused)render(latest);
  }catch(error){
    const warning=byId('warning');
    warning.hidden=false;warning.textContent='Radar service unreachable: '+error.message;
    byId('liveStatus').textContent='SERVICE OFFLINE';
    byId('liveStatus').className='status bad';
  }
}
void refresh();setInterval(()=>{void refresh();},2500);
// Lightweight 3D perspective projection; points are generated ONLY from observed signatures.
function resizeCanvas(){
  const r=canvas.getBoundingClientRect(),d=Math.min(window.devicePixelRatio||1,2);
  canvas.width=Math.max(1,Math.round(r.width*d));canvas.height=Math.max(1,Math.round(r.height*d));
  ctx.setTransform(d,0,0,d,0,0);
  canvasSize={w:r.width,h:r.height};
}
new ResizeObserver(resizeCanvas).observe(canvas);
function position(signature){
  let h=2166136261;
  for(let i=0;i<signature.length;i++){h=Math.imul(h^signature.charCodeAt(i),16777619)>>>0;}
  const a=((h%10000)/10000)*Math.PI*2;
  const z=((((h>>>12)%9000)/9000)*1.76)-.88;
  const r=Math.sqrt(1-z*z);
  return {x:Math.cos(a)*r,y:Math.sin(a)*r,z};
}
function project(v,theta,radius,cx,cy){
  const x=v.x*Math.cos(theta)-v.z*Math.sin(theta);
  const z=v.x*Math.sin(theta)+v.z*Math.cos(theta);
  const scale=1.1/(1.1+z*.21);
  return {x:cx+x*radius*scale,y:cy+v.y*radius*scale,z,scale};
}
function draw(){
  const {w,h}=canvasSize;
  if(w<2||h<2){requestAnimationFrame(draw);return;}
  ctx.clearRect(0,0,w,h);
  const cx=w/2,cy=h*.47,radius=Math.min(w*.34,h*.40,151);
  ctx.save();
  const halo=ctx.createRadialGradient(cx,cy,10,cx,cy,radius*1.45);
  halo.addColorStop(0,'rgba(16,113,183,.22)');halo.addColorStop(1,'rgba(1,17,35,0)');
  ctx.fillStyle=halo;ctx.fillRect(cx-radius*1.5,cy-radius*1.5,radius*3,radius*3);
  // Spherical grid: navigation geometry, not fabricated nodes or links.
  ctx.strokeStyle='rgba(56,180,227,.22)';ctx.lineWidth=1;
  for(let lat=-60;lat<=60;lat+=30){
    ctx.beginPath();
    const phi=lat*Math.PI/180;
    for(let j=0;j<=90;j++){
      const a=j/90*Math.PI*2;
      const p=project({x:Math.cos(phi)*Math.cos(a),y:Math.sin(phi),z:Math.cos(phi)*Math.sin(a)},angle,radius,cx,cy);
      if(j===0)ctx.moveTo(p.x,p.y);else ctx.lineTo(p.x,p.y);
    }ctx.stroke();
  }
  for(let lon=0;lon<180;lon+=30){
    ctx.beginPath();const phi=lon*Math.PI/180;
    for(let j=0;j<=90;j++){
      const a=j/90*Math.PI*2;
      const p=project({x:Math.sin(a)*Math.cos(phi),y:Math.cos(a),z:Math.sin(a)*Math.sin(phi)},angle,radius,cx,cy);
      if(j===0)ctx.moveTo(p.x,p.y);else ctx.lineTo(p.x,p.y);
    }ctx.stroke();
  }
  const points=(latest?.events||[]).slice(0,75).map(e=>{
    const p=project(position(e.signature),angle,radius,cx,cy);return {e,p};
  }).sort((a,b)=>b.p.z-a.p.z);
  for(const {e,p} of points){
    const color=e.policyMatches.length?'255,110,141':e.outcome==='failed'?'171,140,255':'75,229,244';
    ctx.fillStyle='rgba('+color+','+(p.z>0?.42:.95)+')';
    ctx.beginPath();ctx.arc(p.x,p.y,e.policyMatches.length?4:2.6,0,Math.PI*2);ctx.fill();
    if(e.policyMatches.length){
      ctx.strokeStyle='rgba(255,110,141,.55)';
      ctx.beginPath();ctx.arc(p.x,p.y,7,0,Math.PI*2);ctx.stroke();
    }
  }
  // Distinct outer 3D layer: genuine local Kali IDS alerts, never Solana transactions.
  const alerts=(latest?.kali?.events||[]).slice(0,35);
  alerts.forEach((event,i)=>{
    const p=project(position(event.signature+event.observedAt),angle+.6,radius*1.22,cx,cy);
    const rr=event.action==='sensor-reported-block'?4.2:3;
    ctx.fillStyle=event.action==='sensor-reported-block'?'rgba(255,116,140,.95)':'rgba(255,188,105,.85)';
    ctx.beginPath();ctx.moveTo(p.x,p.y-rr);ctx.lineTo(p.x+rr,p.y+rr);ctx.lineTo(p.x-rr,p.y+rr);ctx.closePath();ctx.fill();
  });
  ctx.strokeStyle='rgba(52,203,238,.3)';ctx.beginPath();
  ctx.ellipse(cx,cy+radius*.73,radius*1.13,radius*.28,0,0,Math.PI*2);ctx.stroke();
  if(!(latest?.events?.length)){
    ctx.font='11px ui-sans-serif,system-ui';ctx.fillStyle='#6e9fc1';
    ctx.textAlign='center';ctx.fillText('Awaiting actual chain observations',cx,cy+radius*.85);
  }
  ctx.restore();
  if(!paused && !window.matchMedia('(prefers-reduced-motion: reduce)').matches)angle+=.004;
  requestAnimationFrame(draw);
}
requestAnimationFrame(draw);
