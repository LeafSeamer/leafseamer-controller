import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {loadGuiAssets} from '../../dist/gui-assets.mjs';

export async function verifyHumanProjectionBrowser({dir,service,origin,tls,login,scope,registrationId,
  db,deploy,disconnect,publish,sweep,revoke}) {
  const gui = process.env.LEAFSEAMER_PROJECTION_GUI_ROOT;
  const configuration = path.join(dir,'gui-status.json');
  const output = path.join(dir,'gui-status');
  fs.writeFileSync(configuration,JSON.stringify({site_label:'LeafSeamer',service_id:service.service_id,
    database_instance_id:service.database_instance_id}),{flag:'wx'});
  const result=spawnSync(process.execPath,['scripts/build.mjs','--config',configuration,'--out-dir',output],
    {cwd:gui,stdio:'ignore',timeout:15000});
  assert.equal(result.status,0,'配置工作台构建失败');
  deploy(loadGuiAssets(output,service,origin));
  const {chromium}=createRequire(import.meta.url)(process.env.LEAFSEAMER_GUI_PLAYWRIGHT);
  const spki=crypto.createHash('sha256').update(new crypto.X509Certificate(tls.cert).publicKey.export({type:'spki',format:'der'})).digest('base64');
  const browser=await chromium.launch({executablePath:process.env.LEAFSEAMER_GUI_BROWSER,headless:true,args:['--ignore-certificate-errors-spki-list='+spki]});
  const timer=setInterval(sweep,50);
  try {
    const context=await browser.newContext({viewport:{width:390,height:844}});
    const page=await context.newPage();
    const errors=[];
    page.on('pageerror',error=>errors.push(error.name));
    const seen=[];
    page.on('response',response=>{
      const url=new URL(response.url());
      if(url.origin===origin&&(url.pathname.startsWith('/api/v1/')||url.pathname==='/auth/sessions'))
        seen.push([response.request().method(),url.pathname.replace(/[0-9a-f-]{36}/g,':id'),response.status()]);
    });
    const latest=()=>db.prepare('SELECT r.body_jcs FROM service_event_subscription_revision r JOIN service_event_subscription_head h USING(subscription_id,revision) ORDER BY r.rowid DESC LIMIT 1').pluck().get();
    assert.equal((await page.goto(origin+'/')).status(),200);
    await page.getByLabel('用户名').fill(login.login);
    await page.getByLabel('密码',{exact:true}).fill(login.password);
    await page.getByRole('button',{name:'登录',exact:true}).click();
    const pane=page.getByRole('region',{name:'来源状态订阅'});
    const status=pane.getByRole('status'), scopeInput=pane.getByLabel('已授权范围 JSON');
    const start=pane.getByRole('button',{name:'开始订阅'}), stop=pane.getByRole('button',{name:'停止订阅'});
    const live=()=>status.getByText('正在接收实时状态',{exact:true}).waitFor({timeout:12000});
    const sequence=value=>pane.locator('li .fact').filter({hasText:'连续序号'}).locator('dd').getByText(value,{exact:true}).waitFor({timeout:7000});
    const before=seen.length;
    await scopeInput.fill(JSON.stringify({...scope,projection_profile_ref:{...scope.projection_profile_ref,authority_service_id:crypto.randomUUID()}}));
    await start.click();
    await status.getByText('范围 JSON 无效或属于其他站点',{exact:true}).waitFor({timeout:5000});
    assert.equal(seen.filter(([,route])=>route.startsWith('/api/v1/subscriptions')).length,0);
    assert.equal(seen.slice(before).some(([,route])=>route==='/api/v1/request-contexts'),false);
    await scopeInput.fill(JSON.stringify(scope)); await start.click();
    try { await live(); } catch { assert.fail(JSON.stringify({phase:await status.textContent(),http:seen})); }
    await pane.getByText(registrationId,{exact:true}).waitFor({timeout:5000});
    await sequence('2');
    const first=JSON.parse(latest());
    assert.equal(first.state,'live');assert.equal(first.binding.connection_generation,'1');

    publish('3');await sequence('3');
    disconnect();publish('4');await live();await sequence('4');
    const resumed=JSON.parse(latest());
    assert.equal(resumed.binding.subscription_id,first.binding.subscription_id);
    assert.equal(resumed.binding.connection_generation,'2');assert.equal(resumed.state,'live');
    assert.ok(BigInt(resumed.ack_cursor)>BigInt(first.ack_cursor));
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await stop.click();
    await status.getByText('未订阅',{exact:true}).waitFor({timeout:7000});
    assert.equal(JSON.parse(latest()).state,'closed');
    assert.equal(await pane.getByText(registrationId,{exact:true}).count(),0);

    await start.click();await live();
    await revoke();
    await status.getByText('当前会话无法读取此范围',{exact:true}).waitFor({timeout:10000});
    assert.equal(await pane.getByText(registrationId,{exact:true}).count(),0);
    assert.deepEqual(errors,[]);
    assert.ok(seen.some(([method,route,status])=>method==='GET'&&route.endsWith('/pages/0')&&status===200));
  } finally {
    clearInterval(timer);
    await browser.close();
  }
}
