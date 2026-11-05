import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

export class WireError extends Error {
  constructor(stage,reason,offset) { super(reason); this.stage=stage; this.reason=reason; this.offset=offset; }
  public() { return {stage:this.stage,reason_code:this.reason,...(this.offset===undefined?{}:{byte_offset:this.offset})}; }
}
const compiled=new WeakMap();
const dialect='https://json-schema.org/draft/2020-12/schema';
const escape=s=>s.replaceAll('~','~0').replaceAll('/','~1');

export function compileSchema(source) {
  // 仅可信安装阶段调用；禁止将此函数作为远程Schema编译服务。
  const derived=structuredClone(source),integerPaths=[],rewrites=[];
  const stack=[[derived,'']];let nodes=0;
  while(stack.length) {
    const [node,path]=stack.pop();
    if(++nodes>16384)throw new WireError('schema','schema_budget');
    if(typeof node==='boolean')continue;
    if(!node || typeof node!=='object' || Array.isArray(node))throw new WireError('schema','schema_invalid');
    if(Object.hasOwn(node,'xRawInteger'))throw new WireError('schema','reserved_keyword');
    if(Object.hasOwn(node,'$schema')) {
      if(![dialect,dialect+'#'].includes(node.$schema))throw new WireError('schema','dialect');
      node.$schema=dialect;
    }
    for(const key of ['$ref','$dynamicRef'])if(Object.hasOwn(node,key) && (typeof node[key]!=='string'||!node[key].startsWith('#')))
      throw new WireError('schema','external_reference');
    const types=Array.isArray(node.type)?node.type:[node.type];
    if(types.includes('integer')) {
      integerPaths.push(path+'/type');
      // 同一union中的number保留近似语义；其他成功分支仍由Ajv正常选择。
      if(!types.includes('number'))node.xRawInteger=true;
    }
    for(const key of ['$defs','properties','patternProperties','dependentSchemas'])
      for(const [name,value] of Object.entries(node[key]??{}))stack.push([value,path+'/'+key+'/'+escape(name)]);
    for(const key of ['allOf','anyOf','oneOf','prefixItems'])
      for(const [i,value] of (node[key]??[]).entries())stack.push([value,path+'/'+key+'/'+i]);
    for(const key of ['items','contains','additionalProperties','unevaluatedProperties','unevaluatedItems','propertyNames','not','if','then','else','contentSchema'])
      if(Object.hasOwn(node,key))stack.push([node[key],path+'/'+key]);
    // Ajv跳过properties中的__proto__名称；等价迁移到精确pattern保留该数据字段的约束。
    if(node.properties && Object.hasOwn(node.properties,'__proto__')) {
      const pattern='^__proto__$(?![\\s\\S])',value=node.properties.__proto__;
      node.patternProperties??={};
      const target=path+'/patternProperties/'+escape(pattern),collision=Object.hasOwn(node.patternProperties,pattern);
      node.patternProperties[pattern]=collision?{allOf:[node.patternProperties[pattern],value]}:value;
      delete node.properties.__proto__;
      rewrites.push({source:path+'/properties/__proto__',derived:target+(collision?'/allOf/1':'')});
      if(collision)rewrites.push({source:target,derived:target+'/allOf/0'});
    }
  }
  const ajv=new Ajv2020({strictSchema:true,strictTypes:false,strictTuples:false,strictRequired:false,allErrors:false,passContext:true,ownProperties:true,
    coerceTypes:false,useDefaults:false,removeAdditional:false,validateFormats:true});
  addFormats(ajv);
  ajv.addKeyword({keyword:'xRawInteger',type:'number',schemaType:'boolean',errors:false,
    validate(enabled,value,parent,context) {
      const token=this?.numbers?.get(context.instancePath);
      return enabled===true && token!==undefined && token.integer && token.safe;
    }});
  let validate;
  try { validate=ajv.compile(derived); }
  catch { throw new WireError('schema','schema_compile'); }
  const handle=Object.freeze({integerPaths:Object.freeze(integerPaths.sort()),rewrites:Object.freeze(rewrites.map(Object.freeze))});
  compiled.set(handle,validate);return handle;
}

export function getSchema() { throw new WireError('input','trusted_configuration'); }

export function isSchema(handle) { return compiled.has(handle); }
export function validateValue(handle,value,numbers) {
  const validate=compiled.get(handle);
  if(!validate)throw new WireError('input','trusted_configuration');
  let ok;
  try { ok=validate.call({numbers},value); }
  catch { throw new WireError('schema','schema_execution'); }
  if(ok)return;
  for(const error of validate.errors??[]) {
    const token=numbers.get(error.instancePath);
    if(token && (error.keyword==='xRawInteger'||error.keyword==='type' &&
        (error.params.type==='integer'||Array.isArray(error.params.type)&&error.params.type.includes('integer')))) {
      if(!token.integer)throw new WireError('schema','raw_integer',token.start);
      if(!token.safe)throw new WireError('schema','integer_range',token.start);
    }
  }
  throw new WireError('schema','schema_rejected');
}
