'use strict';
// vpnstack panel — без зависимостей.
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let csrf = sessionStorage.getItem('csrf') || '';
let overview = null, range = '24h';
const colors = ['#2563eb','#16a34a','#dc2626','#d97706','#7c3aed','#0891b2','#db2777','#65a30d','#9333ea'];

async function api(method, path, body) {
  const r = await fetch(path, {method, headers: {'Content-Type': 'application/json', 'X-CSRF': csrf}, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin'});
  if (r.status === 401) { showLogin(); throw new Error('нужен вход'); }
  const ct = r.headers.get('Content-Type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || r.statusText);
  return data;
}

function showLogin() { $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); }
$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(Object.fromEntries(f))});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    csrf = d.csrf; sessionStorage.setItem('csrf', csrf);
    $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); route();
  } catch (err) { $('#loginErr').textContent = err.message; }
});
$('#logout').onclick = async () => { await api('POST', '/api/logout').catch(() => {}); sessionStorage.removeItem('csrf'); showLogin(); };
$('#modalClose').onclick = () => closeModal();
function modal(html) { $('#modalContent').innerHTML = html; $('#modal').classList.remove('hidden'); return $('#modalContent'); }
function closeModal() { $('#modal').classList.add('hidden'); $('#modalContent').innerHTML = ''; }

const fmtBytes = b => { b = +b || 0; const u = ['Б','КБ','МБ','ГБ','ТБ']; let i = 0; while (b >= 1024 && i < 4) { b /= 1024; i++; } return b.toFixed(i ? 1 : 0) + ' ' + u[i]; };
const fmtPct = v => (v == null ? '—' : (+v).toFixed(1) + '%');
const fmtUptime = s => { s = +s; const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600); return d ? `${d} д ${h} ч` : `${h} ч ${Math.floor(s % 3600 / 60)} мин`; };

// Простой SVG-график нескольких рядов.
function chart(series, fmt = v => v.toFixed(1)) {
  const W = 600, H = 150, P = 4;
  const all = Object.values(series).flat();
  if (!all.length) return '<p class="muted">Нет данных — статистика собирается раз в минуту.</p>';
  const t0 = Math.min(...all.map(p => p.t)), t1 = Math.max(...all.map(p => p.t)) || t0 + 1;
  const vmax = Math.max(...all.map(p => p.v), 1e-9);
  let paths = '', legend = '', i = 0;
  for (const [name, pts] of Object.entries(series)) {
    const c = colors[i++ % colors.length];
    const d = pts.map((p, k) => `${k ? 'L' : 'M'}${(P + (p.t - t0) / ((t1 - t0) || 1) * (W - 2 * P)).toFixed(1)},${(H - P - p.v / vmax * (H - 2 * P)).toFixed(1)}`).join('');
    paths += `<path d="${d}" stroke="${c}"/>`;
    legend += `<span><i style="background:${c}"></i>${esc(name)}</span>`;
  }
  const ts = t => new Date(t * 1000).toLocaleString('ru', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'});
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${paths}</svg>
    <div class="row muted" style="justify-content:space-between;font-size:12px"><span>${ts(t0)}</span><span>макс ${esc(fmt(vmax))}</span><span>${ts(t1)}</span></div>
    <div class="legend">${legend}</div>`;
}
async function stats(keys) { return api('GET', `/api/stats?range=${range}&keys=${encodeURIComponent(keys.join(','))}`); }
const rangeSel = () => `<select id="range">${['24h','7d','30d'].map(r => `<option ${r === range ? 'selected' : ''}>${r}</option>`).join('')}</select>`;

// ---------- Обзор ----------
async function viewOverview(el) {
  const [ov, svcs] = await Promise.all([api('GET', '/api/overview'), api('GET', '/api/services')]);
  overview = ov;
  $('#ver').textContent = ov.version;
  const L = ov.last, T = ov.totals;
  const inst = svcs.filter(s => s.installed);
  el.innerHTML = `
  <div class="grid">
    <div class="card kpi"><span class="muted">CPU</span><b>${fmtPct(L['host.cpu'])}</b></div>
    <div class="card kpi"><span class="muted">Память</span><b>${fmtBytes(L['host.mem'])} / ${fmtBytes(L['host.mem_total'])}</b></div>
    <div class="card kpi"><span class="muted">Трафик (всё время, интерфейс)</span><b>↓ ${fmtBytes(T.host?.rx)} ↑ ${fmtBytes(T.host?.tx)}</b></div>
    <div class="card kpi"><span class="muted">${esc(ov.hostname)} · ${esc(ov.public_ip)}</span><b>${fmtUptime(ov.uptime)}</b></div>
  </div>
  ${ov.ota.info && ov.ota.info.available ? `<div class="card">Доступна новая версия vpnstack <b>${esc(ov.ota.info.latest)}</b> — <a href="#settings">Настройки → Обновление</a></div>` : ''}
  <div class="card"><div class="row" style="justify-content:space-between"><h2>Сервисы</h2>${rangeSel()}</div>
  <table><tr><th>Сервис</th><th>Состояние</th><th>Версия</th><th>CPU</th><th>RAM</th><th>Трафик ↓/↑</th><th>Польз.</th></tr>
  ${inst.map(s => `<tr><td>${esc(s.title)}</td><td><span class="badge ${esc(s.status.state)}">${esc(s.status.state)}</span></td><td>${esc(s.version)}</td>
    <td>${fmtPct(L['svc.' + s.id + '.cpu'])}</td><td>${fmtBytes(L['svc.' + s.id + '.mem'])}</td>
    <td>${fmtBytes(T['svc.' + s.id]?.rx)} / ${fmtBytes(T['svc.' + s.id]?.tx)}</td><td>${s.users ? s.users.length : ''}</td></tr>`).join('') || '<tr><td colspan=7 class="muted">Ничего не установлено — откройте «Сервисы».</td></tr>'}
  </table></div>
  <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(520px,1fr))">
    <div class="card"><h2>CPU хоста и сервисов, %</h2><div id="cCpu"></div></div>
    <div class="card"><h2>Память, байт</h2><div id="cMem"></div></div>
    <div class="card"><h2>Трафик интерфейса за минуту/час</h2><div id="cNet"></div></div>
    <div class="card"><h2>Трафик сервисов (↓+↑)</h2><div id="cSvc"></div></div>
  </div>`;
  $('#range').onchange = e => { range = e.target.value; viewOverview(el); };
  const ids = inst.map(s => s.id);
  const d = await stats(['host.cpu', 'host.mem', 'host.rx', 'host.tx', ...ids.flatMap(i => ['svc.' + i + '.cpu', 'svc.' + i + '.mem', 'svc.' + i + '.rx', 'svc.' + i + '.tx'])]);
  const pick = (suffix, base) => Object.fromEntries([[base, d[base] || []], ...ids.map(i => [i, d['svc.' + i + suffix] || []])].filter(([, v]) => v.length));
  $('#cCpu').innerHTML = chart(pick('.cpu', 'host.cpu'), v => v.toFixed(1) + '%');
  $('#cMem').innerHTML = chart(pick('.mem', 'host.mem'), fmtBytes);
  $('#cNet').innerHTML = chart({'↓ rx': d['host.rx'] || [], '↑ tx': d['host.tx'] || []}, fmtBytes);
  const sum = i => (d['svc.' + i + '.rx'] || []).map((p, k) => ({t: p.t, v: p.v + ((d['svc.' + i + '.tx'] || [])[k]?.v || 0)}));
  $('#cSvc').innerHTML = chart(Object.fromEntries(ids.map(i => [i, sum(i)]).filter(([, v]) => v.length)), fmtBytes);
}

// ---------- Сервисы ----------
async function viewServices(el) {
  const svcs = await api('GET', '/api/services');
  el.innerHTML = `<div class="grid">${svcs.map(s => `
    <div class="card"><div class="row" style="justify-content:space-between"><h2>${esc(s.title)}</h2>
      <span class="badge ${esc(s.status.state)}">${s.installed ? esc(s.status.state) : 'не установлен'}</span></div>
      <p class="muted">${esc(s.description)}</p>
      ${s.version ? `<p>Версия: ${esc(s.version)}</p>` : ''}${s.error ? `<p class="err">${esc(s.error)}</p>` : ''}
      ${s.status.detail ? `<p class="muted">${esc(s.status.detail)}</p>` : ''}
      <div class="row">${s.core ? '' : s.installed ? `
        <button data-a="config" data-id="${s.id}">Настроить</button>
        ${s.has_users ? `<button class="sec" data-a="users" data-id="${s.id}">Пользователи (${(s.users || []).length})</button>` : ''}
        ${s.has_links ? `<button class="sec" data-a="links" data-id="${s.id}">Ссылки</button>` : ''}
        <button class="sec" data-a="update" data-id="${s.id}">Обновить</button>
        <button class="sec" data-a="restart" data-id="${s.id}">Перезапуск</button>
        <button class="sec" data-a="logs" data-id="${s.id}">Журнал</button>
        <button class="sec" data-a="files" data-id="${s.id}">Конфиг</button>
        <button class="danger" data-a="remove" data-id="${s.id}">Удалить</button>` :
        `<button data-a="install" data-id="${s.id}">Установить</button>` }
        ${s.core ? `<button class="sec" data-a="logs" data-id="${s.id}">Журнал</button><button class="sec" data-a="files" data-id="${s.id}">Конфиг</button><button class="sec" data-a="update" data-id="${s.id}">Обновить</button>` : ''}
      </div></div>`).join('')}</div>
    <div class="card"><h2>Проверка совместимости</h2><div id="planBox" class="muted">…</div></div>`;
  el.querySelectorAll('button[data-a]').forEach(b => b.onclick = () => serviceAction(svcs.find(s => s.id === b.dataset.id), b.dataset.a));
  api('GET', '/api/plan').then(p => $('#planBox').innerHTML = problemsHTML(p)).catch(e => $('#planBox').textContent = e.message);
}

function problemsHTML(p) {
  const pr = p.problems || [];
  const routes = (p.routes || []).map(r => `<tr><td>${esc(r.name)}</td><td>${esc((r.sni || []).join(', '))}${r.default ? ' <span class="badge">по умолчанию</span>' : ''}</td><td>${esc(r.backend)}${r.proxy_protocol ? ' (PROXY v2)' : ''}</td></tr>`).join('');
  return (pr.length ? `<ul class="problems">${pr.map(x => `<li class="${x.fatal ? 'err' : ''}">${esc(x.msg)} ${x.unit && x.unit.endsWith('.service') ? `<button class="sec" data-stop="${esc(x.unit)}">Остановить ${esc(x.unit)}</button>` : ''}</li>`).join('')}</ul>` : '<p>Проблем не найдено.</p>') +
    (routes ? `<h3>Маршруты TCP 443 по SNI</h3><table><tr><th>Сервис</th><th>SNI</th><th>Куда</th></tr>${routes}</table>` : '');
}
document.addEventListener('click', async e => {
  const u = e.target.dataset && e.target.dataset.stop;
  if (!u || !confirm(`Остановить и отключить ${u}?`)) return;
  const j = await api('POST', '/api/stop-unit', {unit: u});
  watchJob(j.job);
});

function paramForm(s, install) {
  const v = s.values || {};
  const field = p => {
    const val = v[p.key] ?? '';
    let input;
    if (p.type === 'bool') input = `<select name="${p.key}"><option value="true" ${val === 'true' ? 'selected' : ''}>да</option><option value="false" ${val !== 'true' ? 'selected' : ''}>нет</option></select>`;
    else if (p.type === 'select') input = `<select name="${p.key}"><option value="">(по умолчанию)</option>${(p.options || []).map(o => `<option ${o === val ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
    else if (p.type === 'list' && String(val).length > 60) input = `<textarea name="${p.key}" rows="3">${esc(val)}</textarea>`;
    else input = `<input name="${p.key}" value="${esc(val)}" ${p.required ? 'required' : ''} placeholder="${install ? 'авто' : ''}">`;
    return `<label>${esc(p.label)}${p.required ? ' *' : ''}${p.restart ? ' <span class="muted">(перезапуск)</span>' : ''}${input}${p.help ? `<small>${esc(p.help)}</small>` : ''}</label>`;
  };
  const basic = (s.params || []).filter(p => !p.advanced), adv = (s.params || []).filter(p => p.advanced);
  return `<form id="pf">${basic.map(field).join('')}
    ${adv.length ? `<details class="adv"><summary>Дополнительно (ручная настройка)</summary>${adv.map(field).join('')}</details>` : ''}
    <div class="row" style="margin-top:12px"><button type="button" id="pfCheck" class="sec">Проверить</button><button type="submit">${install ? 'Установить' : 'Применить'}</button></div>
    <div id="pfOut"></div></form>`;
}

async function serviceAction(s, a) {
  const id = s.id;
  if (a === 'install' || a === 'config') {
    const m = modal(`<h1>${esc(s.title)}: ${a === 'install' ? 'установка' : 'настройка'}</h1>${paramForm(s, a === 'install')}`);
    const collect = () => { const o = {}; new FormData($('#pf', m)).forEach((v, k) => { if (v !== '' || a === 'config') o[k] = v; }); return o; };
    $('#pfCheck', m).onclick = async () => { try { $('#pfOut', m).innerHTML = problemsHTML(await api('POST', `/api/services/${id}/check`, {params: collect()})); } catch (e) { $('#pfOut', m).innerHTML = `<p class="err">${esc(e.message)}</p>`; } };
    $('#pf', m).onsubmit = async e => { e.preventDefault(); const j = await api('POST', `/api/services/${id}/${a === 'install' ? 'install' : 'reconfigure'}`, {params: collect()}); watchJob(j.job); };
    return;
  }
  if (a === 'remove') {
    const m = modal(`<h1>Удалить ${esc(s.title)}?</h1><label><input type="checkbox" id="purge" style="width:auto"> удалить также данные, пользователей и настройки</label><button class="danger" id="rmGo">Удалить</button>`);
    $('#rmGo', m).onclick = async () => { const j = await api('POST', `/api/services/${id}/remove`, {purge: $('#purge', m).checked}); watchJob(j.job); };
    return;
  }
  if (a === 'update' || a === 'restart') { const j = await api('POST', `/api/services/${id}/${a}`, {}); watchJob(j.job); return; }
  if (a === 'logs') { const d = await api('GET', `/api/services/${id}/logs`); modal(`<h1>Журнал: ${esc(s.title)}</h1><pre>${esc(d.log)}</pre>`); return; }
  if (a === 'files') { const d = await api('GET', `/api/services/${id}/config`); modal(`<h1>Конфигурация: ${esc(s.title)}</h1><p class="muted">Файлы генерируются vpnstack — меняйте параметры через «Настроить».</p>${Object.entries(d).map(([f, c]) => `<h3>${esc(f)}</h3><pre>${esc(c)}</pre>`).join('')}`); return; }
  if (a === 'links') { const d = await api('GET', `/api/services/${id}/links`); modal(`<h1>${esc(s.title)}</h1>${await artifactsHTML(d)}`); bindCopy(); return; }
  if (a === 'users') return usersModal(s);
}

async function usersModal(s) {
  const ov = overview || await api('GET', '/api/overview');
  const T = ov.totals || {};
  const m = modal(`<h1>Пользователи: ${esc(s.title)}</h1>
    <form id="uf" class="row"><input name="name" placeholder="имя (латиница, цифры, -_.)" required style="flex:1"><button>Добавить</button></form>
    <table><tr><th>Имя</th><th>Создан</th><th>Трафик ↓/↑</th><th></th></tr>
    ${(s.users || []).map(u => `<tr><td>${esc(u.name)}</td><td>${u.created ? new Date(u.created).toLocaleDateString('ru') : ''}</td>
      <td>${fmtBytes(T['user.' + s.id + '.' + u.name]?.rx)} / ${fmtBytes(T['user.' + s.id + '.' + u.name]?.tx)}</td>
      <td class="row"><button class="sec" data-show="${esc(u.name)}">Подключение</button><button class="danger" data-del="${esc(u.name)}">✕</button></td></tr>`).join('')}
    </table><div id="uOut"></div>`);
  $('#uf', m).onsubmit = async e => { e.preventDefault(); const j = await api('POST', `/api/services/${s.id}/users`, {name: new FormData(e.target).get('name')}); watchJob(j.job, () => route()); };
  m.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { if (!confirm('Удалить ' + b.dataset.del + '?')) return; const j = await api('DELETE', `/api/services/${s.id}/users/${encodeURIComponent(b.dataset.del)}`); watchJob(j.job, () => route()); });
  m.querySelectorAll('[data-show]').forEach(b => b.onclick = async () => {
    const d = await api('GET', `/api/services/${s.id}/users/${encodeURIComponent(b.dataset.show)}`);
    $('#uOut', m).innerHTML = `<h2>${esc(b.dataset.show)}</h2>` + await artifactsHTML(d); bindCopy();
  });
}

async function qrImg(text) {
  try {
    const r = await fetch('/api/qr', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF': csrf}, body: JSON.stringify({text})});
    if (!r.ok) return '';
    const svg = await r.text();
    return `<div class="qr"><img alt="QR" src="data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}"></div>`;
  } catch { return ''; }
}
async function artifactsHTML(list) {
  let h = '';
  for (const a of list || []) {
    h += `<div class="card"><h3>${esc(a.title)}</h3><pre>${esc(a.value)}</pre><div class="row"><button class="sec" data-copy="${esc(a.value)}">Копировать</button>
      ${a.kind === 'file' ? `<a download="${esc(a.name)}" href="data:text/plain;charset=utf-8,${encodeURIComponent(a.value)}"><button class="sec" type="button">Скачать ${esc(a.name)}</button></a>` : ''}</div>
      ${a.qr ? await qrImg(a.value) : ''}</div>`;
  }
  return h || '<p class="muted">Нет данных.</p>';
}
function bindCopy() { document.querySelectorAll('[data-copy]').forEach(b => b.onclick = () => { navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Скопировано'; }); }

// Журнал задачи в реальном времени.
function watchJob(id, after) {
  const m = modal(`<h1 id="jt">Задача…</h1><pre id="jl">…</pre><p id="je" class="err"></p>`);
  const tick = async () => {
    try {
      const j = await api('GET', '/api/jobs/' + id);
      $('#jt', m).textContent = j.title + (j.done ? (j.error ? ' — ошибка' : ' — готово') : ' — выполняется…');
      const pre = $('#jl', m); pre.textContent = j.log || '…'; pre.scrollTop = pre.scrollHeight;
      if (j.error) $('#je', m).textContent = j.error;
      if (!j.done) setTimeout(tick, 1500); else { if (after) after(); else route(); }
    } catch (e) { $('#je', m).textContent = e.message; }
  };
  tick();
}

// ---------- Задачи ----------
async function viewJobs(el) {
  const jobs = await api('GET', '/api/jobs');
  el.innerHTML = `<div class="card"><h2>Задачи</h2><table><tr><th>Начало</th><th>Задача</th><th>Итог</th><th></th></tr>
    ${jobs.map(j => `<tr><td>${new Date(j.start).toLocaleString('ru')}</td><td>${esc(j.title)}</td><td>${j.done ? (j.error ? '<span class="err">ошибка</span>' : 'готово') : 'выполняется'}</td><td><button class="sec" data-job="${j.id}">Журнал</button></td></tr>`).join('') || '<tr><td colspan=4 class="muted">Пока пусто</td></tr>'}</table></div>`;
  el.querySelectorAll('[data-job]').forEach(b => b.onclick = () => watchJob(b.dataset.job, () => {}));
}

// ---------- Настройки ----------
async function viewSettings(el) {
  const ov = await api('GET', '/api/overview');
  el.innerHTML = `
  <div class="card"><h2>Общие</h2><form id="sf">
    <label>Публичный IPv4 <input name="public_ip" value="${esc(ov.public_ip)}"></label>
    <label>E-mail для Let's Encrypt <input name="email" type="email" value="${esc(ov.email)}"></label>
    <label>Вход TCP 443 <select name="edge_mode"><option value="sni" ${ov.edge_mode !== 'ports' ? 'selected' : ''}>общий вход по SNI (все TCP-сервисы на 443)</option><option value="ports" ${ov.edge_mode === 'ports' ? 'selected' : ''}>отдельные порты</option></select></label>
    <label>Канал версий сервисов <select name="channel"><option ${ov.channel === 'stable' ? 'selected' : ''}>stable</option><option ${ov.channel === 'prerelease' ? 'selected' : ''}>prerelease</option></select></label>
    <button>Сохранить</button></form></div>
  <div class="card"><h2>Обновление vpnstack (OTA)</h2>
    <p>Установлена: <b>${esc(ov.version)}</b> ${ov.ota.info && ov.ota.info.latest ? `· последняя: <b>${esc(ov.ota.info.latest)}</b>` : ''}</p>
    <form id="of"><label><input type="checkbox" name="ota_auto" style="width:auto" ${ov.ota.auto ? 'checked' : ''}> обновлять автоматически</label>
    <label>Канал <select name="ota_channel"><option ${ov.ota.channel !== 'prerelease' ? 'selected' : ''}>stable</option><option ${ov.ota.channel === 'prerelease' ? 'selected' : ''}>prerelease</option></select></label>
    <div class="row"><button>Сохранить</button><button type="button" class="sec" id="otaCheck">Проверить</button><button type="button" class="sec" id="otaApply">Обновить сейчас</button><button type="button" class="sec" id="verCheck">Версии сервисов</button></div></form><p id="otaOut"></p></div>
  <div class="card"><h2>Пароль панели</h2><form id="pw"><label>Текущий <input type="password" name="old" autocomplete="current-password"></label><label>Новый (≥10 символов) <input type="password" name="new" autocomplete="new-password"></label><button>Сменить</button></form>
    <p class="muted">2FA (TOTP): ${ov.totp ? 'включена' : 'выключена'} — управление на сервере: <code>vpnstack panel totp</code>.</p></div>`;
  $('#sf').onsubmit = async e => { e.preventDefault(); const o = Object.fromEntries(new FormData(e.target)); const r = await api('POST', '/api/settings', o); if (r.job) watchJob(r.job); else alert('Сохранено'); };
  $('#of').onsubmit = async e => { e.preventDefault(); const f = new FormData(e.target); await api('POST', '/api/settings', {ota_auto: f.get('ota_auto') === 'on', ota_channel: f.get('ota_channel')}); alert('Сохранено'); };
  $('#otaCheck').onclick = async () => { try { const i = await api('POST', '/api/ota/check'); $('#otaOut').textContent = i.available ? `Доступна ${i.latest}` : `Обновлений нет (последняя ${i.latest})`; } catch (e) { $('#otaOut').textContent = e.message; } };
  $('#otaApply').onclick = async () => { if (confirm('Обновить vpnstack? Панель перезапустится.')) { const j = await api('POST', '/api/ota/apply'); watchJob(j.job, () => {}); } };
  $('#verCheck').onclick = async () => { const j = await api('POST', '/api/ota/versions'); watchJob(j.job, () => {}); };
  $('#pw').onsubmit = async e => { e.preventDefault(); try { await api('POST', '/api/password', Object.fromEntries(new FormData(e.target))); alert('Пароль изменён'); } catch (er) { alert(er.message); } };
}

const views = {overview: viewOverview, services: viewServices, jobs: viewJobs, settings: viewSettings};
async function route() {
  const tab = (location.hash || '#overview').slice(1);
  document.querySelectorAll('header nav a').forEach(a => a.classList.toggle('active', a.dataset.tab === tab));
  const el = $('#main');
  try { await (views[tab] || viewOverview)(el); } catch (e) { if (e.message !== 'нужен вход') el.innerHTML = `<div class="card err">${esc(e.message)}</div>`; }
}
window.addEventListener('hashchange', route);
(async () => {
  try { await api('GET', '/api/overview'); $('#app').classList.remove('hidden'); route(); } catch { showLogin(); }
})();
setInterval(() => { if (!$('#app').classList.contains('hidden') && $('#modal').classList.contains('hidden') && (location.hash || '#overview') === '#overview') route(); }, 60000);
