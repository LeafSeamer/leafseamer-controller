// 仅用于纯JSON原件校验器。数据库关系、当前资格、撤销和时钟不得进入此缓存。
// 键包含完整原文及全部验证参数；调用者可选择深层冻结的只读原件。
function freeze(value){
 if(value!==null&&typeof value==='object'){
  for(const child of Object.values(value))freeze(child);
  Object.freeze(value);
 }
 return value;
}

export function cacheVerifiedDocument(validate,{maxBytes=1048576,maxEntries=64,immutable=false}={}){
 const entries=new Map();let bytes=0;
 const read=immutable?(...input)=>freeze(validate(...input)):validate;
 return (text,...parameters)=>{
  // JSON数组会把undefined、NaN等折叠为null；非字符串参数直接校验，不能共享键。
  if(typeof text!=='string'||parameters.some(value=>typeof value!=='string')||text.length*2>maxBytes)return read(text,...parameters);
  // 序列化后的字符串数组不含实际换行，不必再次转义可能很长的原文。
  const key=JSON.stringify(parameters)+'\n'+text;
  if(entries.has(key)){
   const saved=entries.get(key);entries.delete(key);entries.set(key,saved);
   return immutable?saved.value:structuredClone(saved.value);
  }
  const value=read(text,...parameters);
  if(value===null||value===undefined)return value;
  const size=2*(key.length+JSON.stringify(value).length);
  if(size>maxBytes||maxEntries<1)return value;
  const copy=immutable?value:structuredClone(value);
  while(entries.size>=maxEntries||bytes+size>maxBytes){
   const oldest=entries.keys().next().value;bytes-=entries.get(oldest).size;entries.delete(oldest);
  }
  entries.set(key,{value:copy,size});bytes+=size;return value;
 };
}
