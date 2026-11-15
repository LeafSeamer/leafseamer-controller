import Database from 'better-sqlite3';
// 仅本机服务占用互斥，不承载领域事实；进程退出由SQLite/OS释放锁，不使用可陈旧的PID文件。
export function acquireDatabaseOwner(file){
 const guard=new Database(file+'.owner',{timeout:0});
 try{
  guard.pragma('journal_mode=DELETE',{simple:true});guard.pragma('locking_mode=EXCLUSIVE',{simple:true});
  guard.exec('CREATE TABLE IF NOT EXISTS service_owner_guard(singleton INTEGER PRIMARY KEY CHECK(singleton=1)) STRICT');
  guard.transaction(()=>{guard.prepare('INSERT OR IGNORE INTO service_owner_guard VALUES(1)').run();}).exclusive();
  if(guard.pragma('locking_mode',{simple:true})!=='exclusive')throw new Error('database_owner_mode');
  return Object.freeze({close(){guard.close();}});
 }catch(error){guard.close();throw error;}
}
