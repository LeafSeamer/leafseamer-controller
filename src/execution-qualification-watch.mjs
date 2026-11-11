// 完整资格复核成功后，从该次复核结束重新安排监视；不会修改任何授权期限。
// 调用方不得用历史回放、局部检查或未完成的异步动作刷新监视。
export function executionQualificationWatch({inspect,failed,schedule=setTimeout,cancel=clearTimeout}){
 let stopped=false,timer;
 function refresh(){
  if(stopped)return;cancel(timer);timer=schedule(run,100);timer.unref?.();
 }
 function stop(){stopped=true;cancel(timer);}
 function run(){
  if(stopped)return;
  try{inspect();refresh();}catch(error){stop();failed(error);}
 }
 refresh();return Object.freeze({refresh,stop});
}
