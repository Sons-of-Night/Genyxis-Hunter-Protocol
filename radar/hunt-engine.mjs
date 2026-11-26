import {open, realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isAbsolute, normalize} from 'node:path';
import {createHash} from 'node:crypto';

const KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CVE=/^CVE-[0-9]{4}-[0-9]{4,19}$/;
const ID=/^[a-zA-Z0-9_-]{1,64}$/;
const MAX_FEED=8*1024*1024, MAX_FILE=8*1024*1024;
const FRESH=24*3600_000, POLL=3600_000, HUNT=60_000;
export function parseKev(data){
  if(!data||!Array.isArray(data.vulnerabilities)||!Number.isInteger(data.count)||
     data.count!==data.vulnerabilities.length||data.count<1||data.count>20000||
     typeof data.catalogVersion!=='string'||!Number.isFinite(Date.parse(data.dateReleased))) throw Error('invalid catalog');
  const ids=new Set();
  for(const item of data.vulnerabilities){
    if(!item||typeof item.cveID!=='string'||!CVE.test(item.cveID)||ids.has(item.cveID)) throw Error('invalid CVE');
    ids.add(item.cveID);
  }
  return {ids,version:data.catalogVersion.slice(0,64),releasedAt:Date.parse(data.dateReleased)};
}
function manifest(raw, kind){
  const rows=JSON.parse(raw??'[]');
  if(!Array.isArray(rows)||rows.length> (kind==='file'?16:256)) throw Error('invalid Huntxr inventory');
  const ids=new Set();
  for(const r of rows){
    if(!r||typeof r.id!=='string'||!ID.test(r.id)||ids.has(r.id)) throw Error('invalid asset identifier');
    ids.add(r.id);
    if(kind==='file'){
      if(typeof r.path!=='string'||!isAbsolute(r.path)||normalize(r.path)!==r.path||!(/^[a-f0-9]{64}$/).test(r.sha256??'')) throw Error('invalid file baseline');
    }else if(!Array.isArray(r.cves)||r.cves.length>64||r.cves.some(c=>typeof c!=='string'||!CVE.test(c))) throw Error('invalid CVE inventory');
  }
  return rows;
}
export async function inspectFile(asset){
  let file;
  try{
    if(await realpath(asset.path)!==asset.path) throw Error('path mismatch');
    file=await open(asset.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const before=await file.stat({bigint:true});
    if(!before.isFile()||before.size>BigInt(MAX_FILE)||before.nlink!==1n) throw Error('unsupported file');
    const hash=createHash('sha256');
    const buffer=Buffer.alloc(64*1024);
    let offset=0;
    while(offset<=MAX_FILE){
      const {bytesRead}=await file.read(buffer,0,Math.min(buffer.length,MAX_FILE+1-offset),offset);
      if(!bytesRead)break;
      offset+=bytesRead;
      if(offset>MAX_FILE)throw Error('size limit');
      hash.update(buffer.subarray(0,bytesRead));
    }
    const after=await file.stat({bigint:true});
    if(before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||BigInt(offset)!==after.size||await realpath(asset.path)!==asset.path) throw Error('file changed during read');
    return {id:asset.id,status:hash.digest('hex')===asset.sha256?'match':'drift'};
  }catch{return {id:asset.id,status:'unverified'};}
  finally{if(file)await file.close();}
}
async function boundedJson(response){
  if(!response.ok||!response.body)throw Error('feed unavailable');
  const reader=response.body.getReader(), chunks=[];
  let size=0;
  try{
    while(true){
      const {value,done}=await reader.read();
      if(done)break;
      size+=value.byteLength;
      if(size>MAX_FEED)throw Error('feed too large');
      chunks.push(Buffer.from(value));
    }
  }finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
export function createHunt({env=process.env,now=Date.now,fetchImpl=fetch}={}){
  const enabled=env.HUNTER_RADAR_HUNT_ENABLED==='1';
  const files=manifest(env.HUNTER_RADAR_HUNT_FILES,'file');
  const assets=manifest(env.HUNTER_RADAR_HUNT_CVES,'cve');
  let running=false,feedTimer=null,huntTimer=null,controller=null,feed=null,feedAt=null,feedError=false,checkedAt=null,fileResults=[],busy=false;
  async function refresh(){
    if(!running||controller)return;
    const active=new AbortController();controller=active;
    const timeout=setTimeout(()=>active.abort(),15000);
    try{
      const parsed=parseKev(await boundedJson(await fetchImpl(KEV,{redirect:'error',signal:active.signal,headers:{Accept:'application/json'}})));
      if(active.signal.aborted||!running)return;
      if(parsed.releasedAt>now()+300000|| (feed&&parsed.releasedAt<feed.releasedAt)) throw Error('catalog time invalid');
      feed=parsed;feedAt=now();feedError=false;
    }catch{if(running)feedError=true;}
    finally{clearTimeout(timeout);if(controller===active)controller=null;}
  }
  async function hunt(){
    if(!running||busy)return;
    busy=true;
    try{
      const rows=[];
      for(const asset of files)rows.push(await inspectFile(asset));
      if(running){fileResults=rows;checkedAt=now();}
    }finally{busy=false;}
  }
  function snapshot(){
    const fresh=running&&feedAt!==null&&now()>=feedAt&&now()-feedAt<FRESH&&!feedError;
    const matches=[];
    if(fresh)for(const asset of assets)for(const cve of new Set(asset.cves))if(feed.ids.has(cve))matches.push({asset:asset.id,cve});
    const localFresh=running&&checkedAt!==null&&now()>=checkedAt&&now()-checkedAt<2*HUNT;
    return {enabled,feed:{status:!enabled?'disabled':!running?'stopped':fresh?'fresh':feedError?'unavailable':feed?'stale':'pending',lastSuccessAt:feedAt,catalogVersion:feed?.version??null,catalogReleasedAt:feed?.releasedAt??null,catalogEntries:feed?.ids.size??null},
      inventory:{assets:assets.length,matchCount:fresh?matches.length:null,matches:matches.slice(0,100),scope:'Operator-supplied CVE inventory; matches are remediation priorities, not proof of compromise or version applicability.'},
      integrity:{configured:files.length,lastCheckedAt:checkedAt,status:!enabled?'disabled':!files.length?'not-configured':localFresh?'sampled':'unverified',results:localFresh?fileResults.map(r=>({...r})):[]},
      mode:'defensive observation only'};
  }
  function start(){if(!enabled||running)return;running=true;void refresh();void hunt();feedTimer=setInterval(()=>void refresh(),POLL);huntTimer=setInterval(()=>void hunt(),HUNT);}
  function stop(){running=false;if(feedTimer)clearInterval(feedTimer);if(huntTimer)clearInterval(huntTimer);controller?.abort();}
  return {start,stop,snapshot,refresh,hunt};
}
