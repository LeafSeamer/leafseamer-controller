import {randomUUID} from 'node:crypto';

const sourceId = /^[A-Za-z0-9_.:-]{1,128}$/;
const maximumSleepMs = 60000;
const wakeAfterNs = value => Math.min(maximumSleepMs,Number((value+999999n)/1000000n));

export function referenceTimeScheduler({sourceSlots}, {plan, recover, collect}) {
  if (!Array.isArray(sourceSlots) || sourceSlots.length<1 || sourceSlots.length>4 || new Set(sourceSlots).size!==sourceSlots.length ||
      !sourceSlots.every(slot=>typeof slot==='string' && slot.trim()===slot && sourceId.test(slot))) {
    throw new Error('reference_time_schedule_sources');
  }
  const sources=sourceSlots.map(slot=>({slot,authorization:null,state:'waiting',reason:null,due:0}));
  let timer=null, running=null, started=false, stopped=false, cursor=0;

  function next() {
    const active=sources.filter(item=>item.state!=='blocked');
    if (stopped || active.length===0) return;
    timer=setTimeout(()=>{
      timer=null;
      if (stopped) return;
      running=advance().finally(()=>{ running=null; next(); });
    },Math.max(0,Math.min(...active.map(item=>item.due))-performance.now()));
    timer.unref();
  }

  async function advance() {
    const now=performance.now();
    const offset=Array.from({length:sources.length},(_,i)=>i)
      .find(i=>{ const item=sources[(cursor+i)%sources.length]; return item.state!=='blocked' && item.due<=now; });
    if (offset===undefined) return;
    const index=(cursor+offset)%sources.length, item=sources[index];
    cursor=(index+1)%sources.length;
    try {
      const decision=plan(item.slot,item.authorization);
      if (sources.some(other=>other!==item && other.authorization?.source_digest===decision.authorization.source_digest)) {
        throw new Error('reference_time_schedule_source_alias');
      }
      item.authorization??=decision.authorization;
      if (decision.state==='retirement_required') {
        item.state='recovering';
        await recover(item.slot);
        item.due=performance.now();
      } else if (decision.state==='waiting') {
        item.state='waiting';
        item.due=performance.now()+wakeAfterNs(decision.wait_ns);
      } else {
        item.state='collecting';
        const result=await collect(item.slot,'time-poll.'+randomUUID(),item.authorization);
        if (result.status!=='archived' && result.status!=='control') throw new Error('reference_time_schedule_outcome_unknown');
        item.due=performance.now();
      }
      item.state='waiting';
    } catch(error) {
      if (stopped) return;
      if (error?.message==='time_provider_poll_busy' || error?.message==='time_provider_poll_interval') {
        item.state='waiting'; item.due=performance.now()+100;
        return;
      }
      item.state='blocked';
      item.reason=typeof error?.message==='string' && /^(time_provider_poll_[a-z_]+|reference_time_schedule_[a-z_]+)$/.test(error.message)
        ? error.message : 'reference_time_schedule_unavailable';
    }
  }

  return Object.freeze({
    start() { if (!started && !stopped) { started=true; next(); } },
    close() { stopped=true; clearTimeout(timer); return running; },
    status() { return sources.map(({slot,state,reason})=>({source_slot:slot,state:stopped?'stopped':state,reason})); }
  });
}
