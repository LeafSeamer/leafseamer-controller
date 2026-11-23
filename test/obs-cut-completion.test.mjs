import assert from 'node:assert/strict';
import test from 'node:test';
import {fixedObsCutCompletion} from '../dist/command-settlement.mjs';

const scene='c5204443-5188-4013-9484-c46d4a35b2d2';
const set='d9cbad11-e514-4b0d-b583-d378a49394ac',query='89b16c42-5626-446e-a8b6-726c710cc4e4';
function proof(){
  const frames=['set_send','set_ack','query_send','query_result'].map((kind,index)=>({kind,protocol_request_id:index<2?set:query,
    io_seq:String(11+index),tick_ns:String(21+index),success:true,scene_uuid:index===0||index===3?scene:null}));
  return {scene,source:{deadline:{evidence_timeout_ms:1}},report:{transport_entered_tick_ns:'20',gate_io_seq:'10',
    disposition:'in_flight',proof:'transport_entered',protocol_request_id:set},coverage:{proof:'transport_entered'},receivedTick:26n,committedTick:27n,
    observation:{bytes_written:52,observed_tick_ns:'25',response:{format:'leafseamer-obs-cut-wire/1',target_scene_uuid:scene,frames}}};
}

test('OBS Cut 只使用同次实际发送后的四帧与及时提交的关闭清单裁决',()=>{
  assert.equal(fixedObsCutCompletion(proof()),true);
  for(const [label,change] of [
    ['缺少关闭覆盖',value=>{value.coverage=null;}],
    ['复用请求 ID',value=>{value.observation.response.frames[2].protocol_request_id=set;value.observation.response.frames[3].protocol_request_id=set;}],
    ['报告指向其它发送',value=>{value.report.protocol_request_id=query;}],
    ['阶段顺序错误',value=>{value.observation.response.frames[2].io_seq='12';}],
    ['发送早于实际许可',value=>{value.observation.response.frames[0].tick_ns='19';}],
    ['读回不同节目场景',value=>{value.observation.response.frames[3].scene_uuid='c6527760-c17c-4471-b0cd-5ad8949c5d40';}],
    ['提交恰好到期',value=>{value.committedTick=1000020n;}]
  ]){
    const value=proof();change(value);
    assert.equal(fixedObsCutCompletion(value),false,label);
  }
});
