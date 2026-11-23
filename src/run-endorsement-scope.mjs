import {canonical} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {validateAutomationModel} from './sdk/automation-program.mjs';

const need=(condition,code)=>{if(!condition)throw new IdentityError('run_endorsement_'+code);};
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===keys;
const uuid=value=>typeof value==='string'&&value.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const order=(a,b)=>a<b?-1:a>b?1:0;
export const actionKey=({device_id,action_id,capability_version})=>canonical([device_id,action_id,capability_version]);

function action(value){
 need(exact(value,'action_id,capability_version,device_id')&&uuid(value.device_id)&&typeof value.action_id==='string'&&
  /^[A-Za-z0-9._-]{1,128}$(?![\s\S])/.test(value.action_id)&&typeof value.capability_version==='string'&&value.capability_version.length<=128&&
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$(?![\s\S])/.test(value.capability_version),'action');
 return value;
}
function constrain(values,minimum,maximum){
 if(minimum===-Infinity&&maximum===Infinity)return values;
 return new Map([...values].filter(([,value])=>typeof value==='number'&&value>=minimum&&value<=maximum));
}
function rules(constraints,actions){
 const combined=new Map(),duplicates=new Set();
 for(const condition of constraints){
  need(exact(condition,'action_id,capability_version,device_id,parameter_pointer,rule'),'constraint');
  const {parameter_pointer,rule}=condition,key=actionKey(condition);
  need(actions.has(key)&&typeof parameter_pointer==='string'&&parameter_pointer.length<=1024&&parameter_pointer.isWellFormed()&&
   /^(?:\/(?:[^~/\*]|~[01])*)*$(?![\s\S])/.test(parameter_pointer),'constraint');
  const slot=canonical([key,parameter_pointer]),entry=combined.get(slot)??{values:null,minimum:-Infinity,maximum:Infinity};
  for(const address of combined.keys()){
   const [otherAction,pointer]=JSON.parse(address);
   need(otherAction!==key||pointer===parameter_pointer||!pointer.startsWith(parameter_pointer+'/')&&!parameter_pointer.startsWith(pointer+'/'),'constraint_overlap');
  }
  if(rule?.kind==='range'){
   need(exact(rule,'kind,maximum,minimum')&&Number.isFinite(rule.minimum)&&Number.isFinite(rule.maximum)&&rule.minimum<=rule.maximum,'constraint_range');
   entry.minimum=Math.max(entry.minimum,rule.minimum);entry.maximum=Math.min(entry.maximum,rule.maximum);
  }else{
   const supplied=rule?.kind==='equals'&&exact(rule,'kind,value')?[rule.value]:rule?.kind==='one_of'&&exact(rule,'kind,values')?rule.values:null;
   need(Array.isArray(supplied)&&supplied.length>=1&&supplied.length<=128,'constraint_values');
   const values=new Map(supplied.map(value=>{
    validateAutomationModel('Value',{kind:'literal',value});
    const text=canonical(value);need(typeof text==='string'&&Buffer.byteLength(text)<=65536,'constraint_capacity');return [text,value];
   }));
   need(values.size===supplied.length,'constraint_values');
   if(rule.kind==='one_of')rule.values=[...values].sort(([a],[b])=>order(a,b)).map(([,value])=>value);
   entry.values=entry.values===null?values:new Map([...entry.values].filter(([symbol])=>values.has(symbol)));
  }
  const token=canonical(condition);need(!duplicates.has(token),'constraint_duplicate');duplicates.add(token);
  combined.set(slot,entry);
 }
 for(const value of combined.values()){
  if(value.values!==null)value.values=constrain(value.values,value.minimum,value.maximum);
  need(value.minimum<=value.maximum&&(value.values===null||value.values.size>0),'constraint_empty');
 }
 return combined;
}

export function endorsementScope(deviceActions,parameterConstraints,{allowEmpty=false}={}){
 need(Array.isArray(deviceActions)&&(allowEmpty||deviceActions.length>=1)&&deviceActions.length<=256&&
  Array.isArray(parameterConstraints)&&parameterConstraints.length<=64,'scope_capacity');
 const device_actions=structuredClone(deviceActions).map(action),parameter_constraints=structuredClone(parameterConstraints);
 const actionKeys=new Set(device_actions.map(actionKey));need(actionKeys.size===device_actions.length,'action_duplicate');
 const parameters=rules(parameter_constraints,actionKeys);
 device_actions.sort((a,b)=>order(actionKey(a),actionKey(b)));parameter_constraints.sort((a,b)=>order(canonical(a),canonical(b)));
 need(Buffer.byteLength(canonical({device_actions,parameter_constraints}))<=1048576,'scope_capacity');
 return {device_actions,parameter_constraints,actionKeys,parameters};
}

export function assertEndorsementScopeContains(allowed,requested){
 for(const key of requested.actionKeys)need(allowed.actionKeys.has(key),'action_denied');
 for(const [slot,policy] of allowed.parameters){
  const [key]=JSON.parse(slot);if(!requested.actionKeys.has(key))continue;
  const restriction=requested.parameters.get(slot);need(restriction,'constraint_denied');
  if(restriction.values!==null){
   const values=constrain(restriction.values,policy.minimum,policy.maximum);
   need(values.size===restriction.values.size&&(!policy.values||[...values.keys()].every(value=>policy.values.has(value))),'constraint_denied');
  }else{
   need(restriction.minimum>=policy.minimum&&restriction.maximum<=policy.maximum&&(!policy.values||
    restriction.minimum===restriction.maximum&&policy.values.has(canonical(restriction.minimum))),'constraint_denied');
  }
 }
}

export function assertEndorsementParameters(scope,target,parameters){
 const key=actionKey(target);
 need(scope.actionKeys.has(key),'action_denied');
 for(const [slot,policy] of scope.parameters){
  const [action,pointer]=JSON.parse(slot);
  if(action!==key)continue;
  let value=parameters;
  for(const token of pointer===''?[]:pointer.slice(1).split('/').map(part=>part.replaceAll('~1','/').replaceAll('~0','~'))){
   need(value!==null&&typeof value==='object'&&Object.hasOwn(value,token)&&
    (!Array.isArray(value)||/^(0|[1-9][0-9]*)$/.test(token)),'constraint_denied');
   value=value[token];
  }
  need((policy.values===null||policy.values.has(canonical(value)))&&
   (policy.minimum===-Infinity&&policy.maximum===Infinity||
    typeof value==='number'&&Number.isFinite(value)&&value>=policy.minimum&&value<=policy.maximum),'constraint_denied');
 }
}
