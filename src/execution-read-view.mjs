// 只在一个同步writer调用内复用已完整校验的原件；当前头、资格和时钟不进入缓存。
// 任意本连接写入都会禁用本次视图（包括随后回滚），退出调用即释放全部对象。
// 写入后的独立嵌套调用可建立新视图；退出时恢复已失效的父视图，不能复活父缓存。
const views=new WeakMap();
export function withExecutionReadView(db,read){
 if(!db.inTransaction)throw new Error('execution_read_view_writer');
 const parent=views.get(db);
 if(parent&&!parent.dirty&&parent.version.get()===parent.changes)return read();
 if(parent){parent.values.clear();parent.dirty=true;}
 const version=parent?.version??db.prepare('SELECT total_changes()').pluck();
 const view={version,changes:version.get(),dirty:false,values:new Map()};views.set(db,view);
 try{return read();}finally{if(parent)views.set(db,parent);else views.delete(db);}
}
export function memoExecutionRead(db,kind,key,read){
 const view=views.get(db);if(!view)return read();
 if(!db.inTransaction)throw new Error('execution_read_view_writer');
 const changes=view.version.get();if(changes!==view.changes){view.values.clear();view.dirty=true;}
 if(view.dirty)return read();
 const cacheKey=JSON.stringify([kind,key]);if(view.values.has(cacheKey))return view.values.get(cacheKey);
 const value=read();
 if(view.version.get()!==changes){view.values.clear();view.dirty=true;}
 else if(value!==null&&value!==undefined)view.values.set(cacheKey,value);
 return value;
}
