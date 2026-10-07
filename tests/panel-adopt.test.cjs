// Run with node --test tests/panel-adopt.test.cjs (no dependencies).
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const src = fs.readFileSync(require('node:path').join(__dirname, '../internal/panel/web/app.js'), 'utf8');
const code = src.slice(src.indexOf('const adoptRU'), src.indexOf('// ---------- Задачи'));
const fixture = () => [
  {id: 'hysteria', title: 'Hysteria 2', status: 'imported', origin: {source:'Hysteria', units:['hysteria-server.service']}, users:['legacy']},
  {id: 'tgwp', title: 'TG WEB proxy', status: 'new', origin: {source:'TGWP', units:['caddy.service']}, users:[]},
];
async function setup(found, ids, confirmations = []) {
  const calls = [], prompts = [], alerts = [];
  const button = {dataset:{ad:'migrate-selected'}};
  const el = {innerHTML:'', querySelectorAll: selector => selector === '[data-ad]' ? [button] : ids.map(id => ({dataset:{adSelect:id}}))};
  const context = vm.createContext({
    esc: s => String(s ?? '').replace(/</g, '&lt;'),
    api: async (method, path, body) => { calls.push({method,path,body}); return method === 'GET' ? {report:{found}, adopted:{}} : {job:'job1'}; },
    confirm: prompt => {prompts.push(prompt); return confirmations.length ? confirmations.shift() : true;},
    alert: text => alerts.push(text), watchJob: id => calls.push({watch:id}),
  });
  vm.runInContext(code, context);
  await context.viewAdopt(el);
  await button.onclick();
  return {el, calls, prompts, alerts};
}
test('joint migration includes both IDs and stops only selected origins', async () => {
 const r = await setup(fixture(), ['hysteria','tgwp']);
 const post = r.calls.find(c => c.method === 'POST');
 assert.equal(post.path, '/api/adopt/migrate');
 assert.equal(JSON.stringify(post.body), JSON.stringify({ids:['hysteria','tgwp'],force:false}));
 assert.match(r.prompts[0], /caddy.service/);
 assert.match(r.prompts[0], /hysteria-server.service/);
 assert.match(r.el.innerHTML, /data-ad-select="tgwp"/);
});
test('empty selection does not submit', async () => {
 const r = await setup(fixture(), []);
 assert.equal(r.calls.filter(c => c.method === 'POST').length, 0);
 assert.equal(r.alerts.length, 1);
});
test('all selected risks are shown and require confirmation', async () => {
 const f = fixture(); f[1].risky = ['foreign website'];
 const r = await setup(f, ['hysteria','tgwp'], [true,true]);
 assert.match(r.prompts[0], /foreign website/);
 assert.equal(r.calls.find(c => c.method === 'POST').body.force, true);
});
test('cancelling a risk never migrates', async () => {
 const f = fixture(); f[1].risky = ['foreign website'];
 const r = await setup(f, ['hysteria','tgwp'], [false]);
 assert.equal(r.calls.filter(c => c.method === 'POST').length, 0);
});
test('duplicate installations are rejected', async () => {
 const f = fixture(); f.push({...f[1]});
 const r = await setup(f, ['tgwp']);
 assert.equal(r.calls.filter(c => c.method === 'POST').length, 0);
 assert.equal(r.alerts.length, 1);
});
