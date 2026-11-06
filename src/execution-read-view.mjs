// 只在一个同步writer调用内复用已完整校验的原件；当前头、资格和时钟不进入缓存。
// 任意本连接写入都会禁用本次视图（包括随后回滚），退出调用即释放全部对象。
const views=new WeakMap();
export function withExecutionReadView(db,read){
 if(!db.inTransaction)throw new Error('execution_read_view_writer');
 if(views.has(db))return read();
 const version=db.prepare('SELECT total_changes()').pluck();
 const view={version,changes:version.get(),dirty:false,values:new Map()};views.set(db,view);
 try{return read();}finally{views.delete(db);}
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
