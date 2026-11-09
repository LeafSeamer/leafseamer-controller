// 复用编译后的查询，逐次执行读取；不缓存数据库行、权限、当前头或时间资格。
// 语句仅供本函数使用，避免raw/pluck等结果模式被其他调用者修改。
const connections=new WeakMap(),maximum=128;
export function sqliteRows(db,sql,...args){
 let statements=connections.get(db);if(!statements){statements=new Map();connections.set(db,statements);}
 let query=statements.get(sql);
 if(!query||query.busy){
  query=db.prepare(sql).raw();
  if(!statements.has(sql)){
   if(statements.size>=maximum)statements.delete(statements.keys().next().value);
   statements.set(sql,query);
  }
 }
 const values=query.all(...args),names=query.columns().map(column=>column.name);
 return values.map(row=>Object.fromEntries(names.map((name,index)=>[name,row[index]])));
}
