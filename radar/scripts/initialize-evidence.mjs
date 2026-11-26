import {initializeEvidence} from '../intelligence-core.mjs';
const path=process.env.HUNTER_RADAR_EVIDENCE_PATH;
const key=process.env.HUNTER_RADAR_EVIDENCE_KEY;
if(!path||typeof key!=='string'||!/^[a-f0-9]{64}$/.test(key)){
  console.error('Set protected evidence path and 32-byte hexadecimal key in the environment');
  process.exitCode=1;
}else{
  try{
    const checkpoint=initializeEvidence({path,key:Buffer.from(key,'hex')});
    console.log(JSON.stringify({initialized:true,checkpoint}));
  }catch{
    console.error('Evidence initialization failed; existing state was not overwritten');
    process.exitCode=1;
  }
}
