import test from 'node:test';
import assert from 'node:assert/strict';
import {authoritySourceWindowPolicy,sourceWindowNs,sourceWindowContains} from '../dist/authority-source-window.mjs';

test('旧来源保持两秒，新策略最多五秒，拒绝未知策略和非法窗口',()=>{
 const old={},fresh={source_window_policy:authoritySourceWindowPolicy};
 assert.equal(sourceWindowNs(old),2000000000n);
 assert.equal(sourceWindowNs(fresh),5000000000n);
 assert.equal(sourceWindowContains(old,'10','2000000010'),true);
 assert.equal(sourceWindowContains(old,'10','2000000011'),false);
 assert.equal(sourceWindowContains(fresh,'10','5000000010'),true);
 assert.equal(sourceWindowContains(fresh,'10','5000000011'),false);
 assert.equal(sourceWindowContains(fresh,'10','10'),false);
 assert.equal(sourceWindowContains(fresh,'10','9'),false);
 for(const policy of [null,undefined,'authority-source-window/3'])assert.throws(()=>sourceWindowNs({source_window_policy:policy}));
});
