// 仅用于纯JSON原件校验器。数据库关系、当前资格、撤销和时钟不得进入此缓存。
// 键包含完整原文及全部验证参数；返回独立副本，调用者不能修改缓存原件。
export function cacheVerifiedDocument(validate,{maxBytes=1048576,maxEntries=64}={}){
 const entries=new Map();let bytes=0;
 return (text,...parameters)=>{
  // JSON数组会把undefined、NaN等折叠为null；非字符串参数直接校验，不能共享键。
  if(typeof text!=='string'||parameters.some(value=>typeof value!=='string')||text.length*2>maxBytes)return validate(text,...parameters);
  const key=JSON.stringify([text,...parameters]);
  if(entries.has(key)){
   const saved=entries.get(key);entries.delete(key);entries.set(key,saved);
   return structuredClone(saved.value);
  }
  const value=validate(text,...parameters);
  if(value===null||value===undefined)return value;
  const size=2*(key.length+JSON.stringify(value).length);
  if(size>maxBytes||maxEntries<1)return value;
  const copy=structuredClone(value);
  while(entries.size>=maxEntries||bytes+size>maxBytes){
   const oldest=entries.keys().next().value;bytes-=entries.get(oldest).size;entries.delete(oldest);
  }
  entries.set(key,{value:copy,size});bytes+=size;return value;
 };
}
