/* mock-oidc Entra admin center — a replica of entra.microsoft.com's App
   registrations experience over /admin/api. Dependency-free, strict-CSP safe
   (no inline script; all dynamic text via textContent, like app.js). */

(() => {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  /* ===== icons (16x16; octicon fills + simple stroke glyphs) ===== */

  const OCT = {
    plus: 'M7.75 2a.75.75 0 0 1 .75.75V7h4.25a.75.75 0 0 1 0 1.5H8.5v4.25a.75.75 0 0 1-1.5 0V8.5H2.75a.75.75 0 0 1 0-1.5H7V2.75A.75.75 0 0 1 7.75 2Z',
    sync: 'M1.705 8.005a.75.75 0 0 1 .834.656 5.5 5.5 0 0 0 9.592 2.97l-1.204-1.204a.25.25 0 0 1 .177-.427h3.646a.25.25 0 0 1 .25.25v3.646a.25.25 0 0 1-.427.177l-1.38-1.38A7.002 7.002 0 0 1 1.05 8.84a.75.75 0 0 1 .656-.834ZM8 2.5a5.487 5.487 0 0 0-4.131 1.869l1.204 1.204A.25.25 0 0 1 4.896 6H1.25A.25.25 0 0 1 1 5.75V2.104a.25.25 0 0 1 .427-.177l1.38 1.38A7.002 7.002 0 0 1 14.95 7.16a.75.75 0 0 1-1.49.178A5.5 5.5 0 0 0 8 2.5Z',
    trash: 'M11 1.75V3h2.25a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75ZM4.496 6.675l.66 6.6a.25.25 0 0 0 .249.225h5.19a.25.25 0 0 0 .249-.225l.66-6.6a.75.75 0 0 1 1.492.149l-.66 6.6A1.748 1.748 0 0 1 10.595 15h-5.19a1.748 1.748 0 0 1-1.741-1.575l-.66-6.6a.75.75 0 1 1 1.492-.15ZM6.5 1.75V3h3V1.75a.25.25 0 0 0-.25-.25h-2.5a.25.25 0 0 0-.25.25Z',
    copy: 'M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Zm5-5C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z',
    eye: 'M8 2c1.981 0 3.671.992 4.933 2.078 1.27 1.091 2.187 2.345 2.637 3.023a1.62 1.62 0 0 1 0 1.798c-.45.678-1.367 1.932-2.637 3.023C11.67 13.008 9.981 14 8 14c-1.981 0-3.671-.992-4.933-2.078C1.797 10.83.88 9.576.43 8.898a1.62 1.62 0 0 1 0-1.798c.45-.677 1.367-1.931 2.637-3.022C4.33 2.992 6.019 2 8 2Zm0 2.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z',
    check: 'M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z',
    x: 'M3.72 3.72a.75.75 0 0 1 1.06 0L8 6.94l3.22-3.22a.749.749 0 0 1 1.275.326.749.749 0 0 1-.215.734L9.06 8l3.22 3.22a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215L8 9.06l-3.22 3.22a.751.751 0 0 1-1.042-.018.751.751 0 0 1-.018-1.042L6.94 8 3.72 4.78a.75.75 0 0 1 0-1.06Z',
    pencil: 'M11.013 1.427a1.75 1.75 0 0 1 2.474 0l1.086 1.086a1.75 1.75 0 0 1 0 2.474l-8.61 8.61c-.21.21-.47.364-.756.445l-3.251.93a.75.75 0 0 1-.927-.928l.929-3.25c.081-.286.235-.547.445-.758l8.61-8.61Zm.176 4.823L9.75 4.81l-6.286 6.287a.253.253 0 0 0-.064.108l-.558 1.953 1.953-.558a.253.253 0 0 0 .108-.064Zm1.238-3.763a.25.25 0 0 0-.354 0L10.811 3.75l1.439 1.44 1.263-1.263a.25.25 0 0 0 0-.354Z',
    chev: 'M12.78 5.22a.749.749 0 0 1 0 1.06l-4.25 4.25a.749.749 0 0 1-1.06 0L3.22 6.28a.749.749 0 1 1 1.06-1.06L8 8.939l3.72-3.719a.749.749 0 0 1 1.06 0Z',
    info: 'M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Zm8-6.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM6.5 7.75A.75.75 0 0 1 7.25 7h1a.75.75 0 0 1 .75.75v2.75h.25a.75.75 0 0 1 0 1.5h-2a.75.75 0 0 1 0-1.5h.25v-2h-.25a.75.75 0 0 1-.75-.75ZM8 6a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z',
    search: 'M10.68 11.74a6 6 0 0 1-7.922-8.982 6 6 0 0 1 8.982 7.922l3.04 3.04a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215ZM11.5 7a4.5 4.5 0 1 0-9 0 4.5 4.5 0 0 0 9 0Z'
  };

  // Stroke glyphs for the platform tiles (fill=none, stroke=currentColor).
  const STROKE = {
    globe: 'M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13Zm0 0c-1.8 0-3.2 2.9-3.2 6.5s1.4 6.5 3.2 6.5 3.2-2.9 3.2-6.5S9.8 1.5 8 1.5ZM1.8 6h12.4M1.8 10h12.4',
    code: 'M4.5 4.5 1.5 8l3 3.5M11.5 4.5l3 3.5-3 3.5M9.5 3.5l-3 9',
    device: 'M4.75 1.5h6.5c.69 0 1.25.56 1.25 1.25v10.5c0 .69-.56 1.25-1.25 1.25h-6.5C4.06 14.5 3.5 13.94 3.5 13.25V2.75c0-.69.56-1.25 1.25-1.25Zm2.25 10.75h2',
    key: 'M5 11.5 11.5 5m0 0a2.75 2.75 0 1 0 0-3.5 2.75 2.75 0 0 0 0 3.5Zm-8 6.5a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm0 0 2-2'
  };

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    if (OCT[name]) {
      svg.setAttribute('fill', 'currentColor');
      p.setAttribute('d', OCT[name]);
    } else {
      svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor');
      svg.setAttribute('stroke-width', '1.5');
      svg.setAttribute('stroke-linecap', 'round');
      svg.setAttribute('stroke-linejoin', 'round');
      p.setAttribute('d', STROKE[name]);
    }
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('aria-hidden', 'true');
    svg.appendChild(p);
    return svg;
  }

  /* ===== DOM helpers ===== */

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function add(parent, child) { parent.appendChild(child); return child; }

  function iconBtn(iconName, title, danger) {
    const b = el('button', 'iconbtn' + (danger ? ' danger' : ''));
    b.type = 'button';
    b.title = title;
    b.setAttribute('aria-label', title);
    b.appendChild(icon(iconName));
    return b;
  }
  function copyBtn(getText, title) {
    const b = iconBtn('copy', title || 'Copy to clipboard');
    b.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(getText());
        toast('Copied to clipboard');
      } catch (err) {
        toast('Copy failed: ' + err.message, true);
      }
    });
    return b;
  }
  function ghostInput() {
    const input = el('input');
    input.type = 'text';
    input.style.background = 'transparent';
    input.style.border = 'none';
    input.style.borderBottom = '1px solid var(--gray-40)';
    input.style.borderRadius = '0';
    return input;
  }

  /* ===== API ===== */

  async function api(path, opts) {
    const res = await fetch('/admin/api/' + path, opts);
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try {
        const doc = await res.json();
        if (doc && doc.error) msg = doc.error;
      } catch (err) { /* keep the status message */ }
      throw new Error(msg);
    }
    return res.json();
  }
  const DEL = { method: 'DELETE' };
  function POSTJSON(body) {
    return { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  }
  function PUT(body) {
    return { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  }

  /* ===== toast ===== */

  let toastTimer = null;
  function toast(msg, isError) {
    const t = $('#toast');
    t.classList.toggle('err', !!isError);
    t.classList.remove('fade');
    const i = el('span');
    i.appendChild(icon(isError ? 'x' : 'check'));
    t.replaceChildren(i, el('span', null, msg));
    t.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      t.classList.add('fade');
      setTimeout(() => t.classList.add('hidden'), 350);
    }, 4000);
  }

  /* ===== modal ===== */

  // openModal({title, body(bodyEl, close) -> node, actions:[{label, primary, danger, onClick(close)}]})
  function openModal(cfg) {
    const root = $('#modal-root');
    const backdrop = el('div', 'modal-backdrop');
    const modal = el('div', 'modal');
    root.replaceChildren(backdrop, modal);
    const close = () => root.replaceChildren();
    backdrop.addEventListener('click', close);
    const head = add(modal, el('div', 'modal-head'));
    add(head, el('h2', null, cfg.title));
    cfg.body(add(modal, el('div', 'modal-body')), close);
    const foot = add(modal, el('div', 'modal-foot'));
    for (const a of cfg.actions || []) {
      const b = add(foot, el('button', 'cmd' + (a.primary ? ' primary' : '') + (a.danger ? ' danger' : ''), a.label));
      b.type = 'button';
      b.addEventListener('click', () => a.onClick(close));
    }
    const cancel = add(foot, el('button', 'cmd', 'Cancel'));
    cancel.type = 'button';
    cancel.addEventListener('click', close);
  }

  function confirmModal(title, message, onOk) {
    openModal({
      title,
      body: (pane) => { add(pane, el('p', null, message)); },
      actions: [{ label: 'Delete', danger: true, onClick: async (close) => { close(); await onOk(); } }]
    });
  }

  /* ===== formatting ===== */

  function fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleDateString(undefined, { year: 'numeric', month: '2-digit', day: '2-digit' }) +
      ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }
  function expired(iso) { return !!iso && new Date(iso) < new Date(); }

  const PLATFORMS = [
    { value: 'web', label: 'Web', icon: 'globe', desc: 'Web applications using authorization code flow' },
    { value: 'spa', label: 'Single-page application (SPA)', icon: 'code', desc: 'JavaScript applications with a backend' },
    { value: 'mobileAndDesktop', label: 'Mobile and desktop applications', icon: 'device', desc: 'Mobile and desktop apps using embedded browsers' }
  ];
  const PLATFORM_LABELS = Object.fromEntries(PLATFORMS.map((p) => [p.value, p.label]));
  const CLAIM_SOURCES = [
    'user.department', 'user.companyname', 'user.employeeid', 'user.jobtitle',
    'user.officelocation', 'user.extensionattribute1', 'user.extensionattribute2', 'user.extensionattribute3'
  ];

  /* ===== state ===== */

  let snapshot = null;  // the GET entra document
  let fetchError = null;
  const listState = { tab: 'all', query: '' };
  const revealed = new Set(); // secret IDs whose value is shown in the table

  function apps() { return (snapshot && snapshot.apps) || []; }
  function appById(id) { return apps().find((a) => a.clientId === id); }
  function tenants() { return (snapshot && snapshot.tenants) || []; }
  function tenantName(tid) {
    if (!tid) return '';
    const t = tenants().find((t) => t.tid === tid);
    return t ? t.name : tid;
  }
  function audienceLabel(app) {
    if (app.signInAudience === 'AzureADMultipleOrgs') return 'Multiple Entra ID tenants';
    return 'Single tenant only - ' + (tenantName(app.tid) || app.tid);
  }

  /* ===== routing ===== */

  function parseHash() {
    const h = decodeURIComponent(location.hash.replace(/^#/, ''));
    const segs = h.split('/').filter(Boolean);
    if (segs[0] !== 'apps' || segs.length === 1) return { view: 'apps' };
    if (segs[1] === 'new') return { view: 'new' };
    return { view: 'app', clientId: segs[1], blade: segs[2] || 'overview' };
  }

  async function reload() {
    try {
      snapshot = await api('entra');
      fetchError = null;
    } catch (err) {
      snapshot = null;
      fetchError = err;
    }
  }

  async function render() {
    if (!snapshot && !fetchError) await reload();
    const view = $('#view');
    view.replaceChildren();
    if (fetchError) return drawOff(view);
    const route = parseHash();
    if (route.view === 'apps') return drawApps(view);
    if (route.view === 'new') return drawNew(view);
    const app = appById(route.clientId);
    if (!app) { location.hash = '#/apps'; return; }
    drawAppFrame(view, app, route.blade);
  }

  /* ===== shared chrome ===== */

  // parts: the trail after "Home › Microsoft Entra", last item is the current page.
  function crumbs(view, parts) {
    const c = add(view, el('nav', 'crumbs'));
    const home = add(c, el('a', null, 'Home'));
    home.href = '#/apps';
    add(c, el('span', 'sep', '›'));
    const idp = add(c, el('a', null, 'Microsoft Entra'));
    idp.href = '#/apps';
    for (const p of parts) {
      add(c, el('span', 'sep', '›'));
      add(c, el('span', null, p));
    }
    return c;
  }

  function drawOff(view) {
    crumbs(view, ['App registrations']);
    add(view, el('h1', 'page-title', 'App registrations'));
    const empty = add(view, el('div', 'empty-state'));
    add(empty, el('p', null, 'Entra mode is not available on this server.'));
    const p = add(empty, el('p'));
    const a = add(p, el('a', null, 'Open the mock-oidc admin to configure it'));
    a.href = '/admin/#entra';
  }

  /* ===== list blade ===== */

  function drawApps(view) {
    crumbs(view, ['App registrations']);
    const head = add(view, el('div', 'page-head'));
    add(head, el('h1', 'page-title', 'App registrations'));

    const bar = add(view, el('div', 'cmdbar'));
    const newBtn = add(bar, el('button', 'cmd primary'));
    newBtn.type = 'button';
    newBtn.appendChild(icon('plus'));
    add(newBtn, el('span', null, 'New registration'));
    newBtn.addEventListener('click', () => { location.hash = '#/apps/new'; });
    const refresh = add(bar, el('button', 'cmd'));
    refresh.type = 'button';
    refresh.appendChild(icon('sync'));
    add(refresh, el('span', null, 'Refresh'));
    refresh.addEventListener('click', async () => { await reload(); render(); });

    const tabs = add(view, el('div', 'tabs'));
    const counts = { all: apps().length, owned: apps().length, deleted: 0 };
    for (const [id, label] of [['all', 'All applications'], ['owned', 'Owned applications'], ['deleted', 'Deleted applications']]) {
      const b = add(tabs, el('button', 'tab', label + ' (' + counts[id] + ')'));
      b.type = 'button';
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', String(listState.tab === id));
      b.addEventListener('click', () => { listState.tab = id; render(); });
    }

    const toolbar = add(view, el('div', 'toolbar'));
    const box = add(toolbar, el('div', 'searchbox'));
    box.appendChild(icon('search'));
    const input = add(box, el('input'));
    input.type = 'text';
    input.placeholder = 'Search by display name or application ID';
    input.value = listState.query;

    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table', 'list'));
    const hr = add(add(table, el('thead')), el('tr'));
    for (const h of ['Display name', 'Application (client) ID', 'Directory (tenant) ID', 'Created on']) {
      add(hr, el('th', null, h));
    }
    const body = add(table, el('tbody'));

    function drawAppRows() {
      body.replaceChildren();
      if (listState.tab === 'deleted') {
        const td = add(add(body, el('tr')), el('td'));
        td.colSpan = 4;
        add(td, el('div', 'empty-state', 'There are no deleted applications to display.'));
        return;
      }
      const q = listState.query;
      const rows = apps().filter((a) => !q || a.name.toLowerCase().includes(q) || a.clientId.toLowerCase().includes(q));
      if (!rows.length) {
        const td = add(add(body, el('tr')), el('td'));
        td.colSpan = 4;
        add(td, el('div', 'empty-state',
          "You don't have any app registrations to display. Select New registration to create one."));
        return;
      }
      for (const a of rows) {
        const tr = add(body, el('tr'));
        const nameTd = add(tr, el('td'));
        const link = add(nameTd, el('a', null, a.name));
        link.href = '#/apps/' + encodeURIComponent(a.clientId);
        const bits = [];
        if ((a.redirectUris || []).length) bits.push(a.redirectUris.length + ' redirect URI' + (a.redirectUris.length > 1 ? 's' : ''));
        if ((a.secrets || []).length) bits.push(a.secrets.length + ' secret' + (a.secrets.length > 1 ? 's' : ''));
        if (bits.length) add(nameTd, el('div', 'dim', bits.join(' · ')));
        add(tr, el('td', 'mono', a.clientId)).title = a.clientId;
        add(tr, el('td', null, a.tid ? tenantName(a.tid) : 'Any tenant (multitenant)'));
        add(tr, el('td', null, fmtDate(a.createdOn)));
      }
    }
    drawAppRows();
    input.addEventListener('input', () => {
      listState.query = input.value.trim().toLowerCase();
      drawAppRows();
    });
  }

  /* ===== new registration blade ===== */

  function drawNew(view) {
    crumbs(view, ['App registrations', 'New registration']);
    add(view, el('h1', 'page-title', 'New registration'));

    const form = add(view, el('form', 'form'));
    const nameField = add(form, el('div', 'field'));
    const nameLabel = add(nameField, el('label', 'req', 'Name'));
    nameLabel.setAttribute('for', 'reg-name');
    const nameInput = add(nameField, el('input'));
    nameInput.type = 'text';
    nameInput.id = 'reg-name';
    nameInput.placeholder = 'Enter a display name, for example identity-client-app';
    const nameErr = add(nameField, el('div', 'error hidden', 'The Name field is required.'));

    const acctField = add(form, el('div', 'field'));
    add(acctField, el('span', 'req', 'Supported account types')).style.display = 'block';
    const acctSelect = add(acctField, el('select'));
    for (const t of tenants()) {
      add(acctSelect, el('option', null, 'Single tenant only - ' + t.name)).value = t.tid;
    }
    add(acctSelect, el('option', null, 'Multiple Entra ID tenants')).value = '';
    for (const label of ['Any Entra ID Tenant + Personal Microsoft accounts', 'Personal accounts only']) {
      const o = add(acctSelect, el('option', null, label + ' (not part of the mock)'));
      o.disabled = true;
    }
    add(acctField, el('div', 'hint', 'Personal Microsoft accounts are not emulated by mock-oidc.'));

    const redirField = add(form, el('div', 'field'));
    add(redirField, el('label', null, 'Redirect URI (optional)')).setAttribute('for', 'reg-redir');
    const redirRow = add(redirField, el('div', 'rowadd'));
    redirRow.style.paddingLeft = '0';
    const platform = add(redirRow, el('select'));
    platform.style.width = '240px';
    platform.style.flex = 'none';
    add(platform, el('option', null, 'Select a platform…')).value = '';
    for (const p of PLATFORMS) add(platform, el('option', null, p.label)).value = p.value;
    const uri = add(redirRow, el('input'));
    uri.type = 'url';
    uri.id = 'reg-redir';
    uri.placeholder = 'https://contoso.com/auth';
    add(redirField, el('div', 'hint',
      'A registered redirect URI is enforced: authorize rejects any other redirect_uri (AADSTS50011). ' +
      'Leave it empty to accept any redirect URI, the mock default.'));

    const actions = add(form, el('div', 'form-actions'));
    const cancel = add(actions, el('button', 'cmd', 'Cancel'));
    cancel.type = 'button';
    cancel.addEventListener('click', () => { location.hash = '#/apps'; });
    const register = add(actions, el('button', 'cmd primary', 'Register'));
    register.type = 'submit';

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const name = nameInput.value.trim();
      if (!name) {
        nameErr.classList.remove('hidden');
        nameInput.classList.add('invalid');
        return;
      }
      const body = { name, tid: acctSelect.value };
      if (platform.value && uri.value.trim()) body.redirectUris = [{ platform: platform.value, uri: uri.value.trim() }];
      register.disabled = true;
      try {
        const created = await api('entra/apps', POSTJSON(body));
        toast('Successfully registered "' + created.name + '"');
        await reload();
        location.hash = '#/apps/' + encodeURIComponent(created.clientId);
      } catch (err) {
        toast(err.message, true);
        register.disabled = false;
      }
    });
  }

  /* ===== app frame ===== */

  const MENU = [
    { id: 'overview', label: 'Overview' },
    { id: 'quickstart', label: 'Quickstart', dim: true },
    { id: null, label: 'Manage', group: true },
    { id: 'branding', label: 'Branding & properties', dim: true },
    { id: 'authentication', label: 'Authentication' },
    { id: 'certificates', label: 'Certificates & secrets' },
    { id: 'token', label: 'Token configuration' },
    { id: 'permissions', label: 'API permissions', dim: true },
    { id: 'expose', label: 'Expose an API', dim: true },
    { id: 'roles', label: 'App roles' },
    { id: 'owners', label: 'Owners', dim: true },
    { id: 'usage', label: 'API usage', dim: true }
  ];

  function drawAppFrame(view, app, blade) {
    crumbs(view, ['App registrations', app.name]);
    add(view, el('h1', 'page-title', app.name));

    const layout = add(view, el('div', 'app-layout'));
    const menu = add(layout, el('nav', 'app-menu'));
    menu.setAttribute('aria-label', app.name + ' menu');
    for (const m of MENU) {
      if (m.group) { add(menu, el('div', 'group-label', m.label)); continue; }
      const item = add(menu, el('button', 'item' + (blade === m.id ? ' active' : '') + (m.dim ? ' dim' : ''), m.label));
      item.type = 'button';
      if (m.dim) item.title = 'Not part of the mock';
      else item.addEventListener('click', () => {
        location.hash = '#/apps/' + encodeURIComponent(app.clientId) + '/' + m.id;
      });
    }
    const pane = add(layout, el('div', 'app-pane'));
    switch (blade) {
      case 'authentication': return drawAuthentication(pane, app);
      case 'certificates': return drawCertificates(pane, app);
      case 'roles': return drawRoles(pane, app);
      case 'token': return drawTokenConfig(pane, app);
      default: return drawOverview(pane, app);
    }
  }

  /* --- Overview --- */

  function drawOverview(pane, app) {
    const bar = add(pane, el('div', 'cmdbar'));
    const endpoints = add(bar, el('button', 'cmd'));
    endpoints.type = 'button';
    endpoints.appendChild(icon('info'));
    add(endpoints, el('span', null, 'Endpoints'));
    endpoints.addEventListener('click', () => showEndpoints(app));
    add(bar, el('span', 'spacer'));
    const del = add(bar, el('button', 'cmd danger'));
    del.type = 'button';
    del.appendChild(icon('trash'));
    add(del, el('span', null, 'Delete'));
    del.addEventListener('click', () => {
      confirmModal('Delete application registration',
        'Delete "' + app.name + '"? Its client ID "' + app.clientId +
        '" stops working immediately (in-memory state; "Reset to config" restores the seed).',
        async () => {
          try {
            await api('entra/apps/' + encodeURIComponent(app.clientId), DEL);
            toast('Successfully deleted "' + app.name + '"');
            await reload();
            location.hash = '#/apps';
          } catch (err) { toast(err.message, true); }
        });
    });

    const panel = add(pane, el('section', 'essentials'));
    const head = add(panel, el('button', 'essentials-head'));
    head.type = 'button';
    head.appendChild(icon('chev'));
    add(head, el('span', null, 'Essentials'));
    head.addEventListener('click', () => panel.classList.toggle('collapsed'));
    const dl = add(panel, el('dl', 'essentials-body'));

    function addRow(label, build) {
      add(dl, el('dt', null, label));
      build(add(dl, el('dd')));
    }
    addRow('Name', (dd) => {
      add(dd, el('span', null, app.name));
      dd.appendChild(iconBtn('pencil', 'Rename'));
      dd.lastChild.addEventListener('click', () => renameApp(app));
    });
    addRow('Application (client) ID', (dd) => {
      add(dd, el('span', 'mono', app.clientId));
      dd.appendChild(copyBtn(() => app.clientId));
    });
    addRow('Directory (tenant) ID', (dd) => {
      if (app.tid) {
        add(dd, el('span', null, tenantName(app.tid) + ' '));
        add(dd, el('span', 'mono dim', app.tid));
        dd.appendChild(copyBtn(() => app.tid));
      } else {
        add(dd, el('span', null, 'Any tenant (multitenant)'));
      }
    });
    addRow('Object ID', (dd) => {
      add(dd, el('span', 'mono', app.objectId));
      dd.appendChild(copyBtn(() => app.objectId));
    });
    addRow('Supported account types', (dd) => add(dd, el('span', null, audienceLabel(app))));
    addRow('Status', (dd) => add(dd, el('span', 'status-ok', '✓ Enabled')));
    addRow('Created on', (dd) => add(dd, el('span', null, fmtDate(app.createdOn))));

    if ((app.redirectUris || []).length) {
      const sec = add(pane, el('section', 'section'));
      add(sec, el('h2', null, 'Redirect URIs'));
      const list = add(sec, el('div', 'rowlist'));
      for (const r of app.redirectUris) {
        const item = add(list, el('div', 'rowitem'));
        add(item, el('span', 'pill ' + r.platform, PLATFORM_LABELS[r.platform] || r.platform));
        add(item, el('span', 'mono grow', r.uri));
      }
    }
  }

  function renameApp(app) {
    let input;
    openModal({
      title: 'Rename application',
      body: (pane) => {
        const f = add(pane, el('div', 'field'));
        add(f, el('label', 'req', 'Name')).setAttribute('for', 'rename-input');
        input = add(f, el('input'));
        input.type = 'text';
        input.id = 'rename-input';
        input.value = app.name;
      },
      actions: [{
        label: 'Save', primary: true, onClick: async (close) => {
          const name = input.value.trim();
          if (!name) { toast('The Name field is required.', true); return; }
          try {
            await api('entra/apps/' + encodeURIComponent(app.clientId), PUT(appBody({ ...app, name })));
            toast('Successfully renamed the application');
            close();
            await reload();
            render();
          } catch (err) { toast(err.message, true); }
        }
      }]
    });
  }

  function showEndpoints(app) {
    const base = location.origin + '/' + snapshot.basePath;
    const tid = app.tid || 'organizations';
    const rows = [
      ['Issuer (v2.0)', base + '/' + tid + '/v2.0'],
      ['Authorize', base + '/' + tid + '/oauth2/v2.0/authorize'],
      ['Token', base + '/' + tid + '/oauth2/v2.0/token'],
      ['Keys (JWKS)', base + '/' + tid + '/discovery/v2.0/keys'],
      ['OpenID configuration', base + '/' + tid + '/v2.0/.well-known/openid-configuration']
    ];
    openModal({
      title: 'Endpoints',
      body: (pane) => {
        for (const [label, url] of rows) {
          const kv = add(pane, el('dl', 'kv'));
          add(kv, el('dt', null, label));
          const dd = add(kv, el('dd'));
          add(dd, el('span', 'mono', url));
          dd.appendChild(copyBtn(() => url));
        }
        const bar = add(pane, el('div', 'infobar'));
        bar.appendChild(icon('info'));
        add(bar, el('span', null, tid === 'organizations'
          ? 'Multitenant app: any tenant GUID works in place of "organizations", plus "common".'
          : "Tenant-specific endpoints of this app's directory."));
      }
    });
  }

  /* --- editable blades: shared save bar --- */

  function appBody(app) {
    return {
      name: app.name,
      tid: app.tid || '',
      signInAudience: app.signInAudience,
      redirectUris: app.redirectUris || [],
      roles: app.roles || [],
      claims: app.claims || []
    };
  }

  // saveBar renders the Save/Discard command bar for an editable blade and
  // returns {mark}: mark() flags the draft dirty and enables both buttons.
  function saveBar(pane, app, getDraft) {
    let dirty = false;
    const bar = add(pane, el('div', 'cmdbar'));
    const save = add(bar, el('button', 'cmd primary', 'Save'));
    save.type = 'button';
    const discard = add(bar, el('button', 'cmd', 'Discard'));
    discard.type = 'button';
    const setEnabled = () => {
      save.disabled = !dirty;
      discard.disabled = !dirty;
    };
    setEnabled();
    save.addEventListener('click', async () => {
      save.disabled = true;
      try {
        await api('entra/apps/' + encodeURIComponent(app.clientId), PUT(appBody(getDraft())));
        toast('Successfully updated the application');
        await reload();
        render();
      } catch (err) {
        toast(err.message, true);
        setEnabled();
      }
    });
    discard.addEventListener('click', () => render());
    return {
      mark: () => { dirty = true; setEnabled(); }
    };
  }

  /* --- Authentication --- */

  function drawAuthentication(pane, app) {
    const local = structuredClone(app);
    const bar = saveBar(pane, app, () => local);
    const mark = bar.mark;

    const sec = add(pane, el('section', 'section'));
    add(sec, el('h2', null, 'Redirect URIs'));
    add(sec, el('p', 'note',
      'Redirect URIs are enforced for this app: an authorize request with any other redirect_uri is rejected with AADSTS50011. ' +
      'An app without redirect URIs accepts any redirect URI.'));
    const list = add(sec, el('div', null));
    const addPlatform = add(sec, el('button', 'cmd'));
    addPlatform.type = 'button';
    addPlatform.appendChild(icon('plus'));
    add(addPlatform, el('span', null, 'Add a platform'));
    addPlatform.addEventListener('click', () => {
      openModal({
        title: 'Configure platforms',
        body: (p) => {
          const tiles = add(p, el('div', 'tiles'));
          for (const plat of PLATFORMS) {
            const tile = add(tiles, el('button', 'tile'));
            tile.type = 'button';
            tile.appendChild(icon(plat.icon));
            add(tile, el('span', null, plat.label));
            add(tile, el('span', 't-desc', plat.desc));
            tile.addEventListener('click', () => {
              local.redirectUris = local.redirectUris || [];
              local.redirectUris.push({ platform: plat.value, uri: '' });
              mark();
              $('#modal-root').replaceChildren();
              drawList();
            });
          }
        }
      });
    });

    function drawList() {
      list.replaceChildren();
      const groups = new Map();
      for (const r of local.redirectUris || []) {
        if (!groups.has(r.platform)) groups.set(r.platform, []);
        groups.get(r.platform).push(r);
      }
      if (!groups.size) add(list, el('div', 'empty-state', 'No redirect URIs configured.'));
      for (const [platform, uris] of groups) {
        const box = add(list, el('div', 'rowlist'));
        box.style.marginBottom = '12px';
        for (const r of uris) {
          const item = add(box, el('div', 'rowitem'));
          add(item, el('span', 'pill ' + platform, PLATFORM_LABELS[platform] || platform));
          const input = ghostInput();
          input.type = 'url';
          input.classList.add('grow');
          input.value = r.uri;
          input.placeholder = 'https://contoso.com/auth';
          input.addEventListener('input', () => { r.uri = input.value.trim(); mark(); });
          item.appendChild(input);
          const x = add(item, iconBtn('x', 'Remove redirect URI', true));
          x.addEventListener('click', () => {
            local.redirectUris = local.redirectUris.filter((u) => u !== r);
            mark();
            drawList();
          });
        }
        const addRowEl = add(box, el('div', 'rowadd'));
        const inp = add(addRowEl, el('input'));
        inp.type = 'url';
        inp.placeholder = 'Add another ' + (PLATFORM_LABELS[platform] || platform) + ' redirect URI…';
        const btn = add(addRowEl, el('button', 'cmd', 'Add URI'));
        btn.type = 'button';
        const doAdd = () => {
          const v = inp.value.trim();
          if (!v) return;
          local.redirectUris.push({ platform, uri: v });
          mark();
          drawList();
        };
        btn.addEventListener('click', doAdd);
        inp.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); doAdd(); } });
      }
    }
    drawList();

    const note = add(pane, el('div', 'infobar warn'));
    note.appendChild(icon('info'));
    add(note, el('span', null, 'Front-channel logout URLs, implicit grant and hybrid flows are not part of the mock.'));
  }

  /* --- Certificates & secrets --- */

  function drawCertificates(pane, app) {
    const certs = add(pane, el('section', 'section'));
    add(certs, el('h2', null, 'Certificates'));
    add(certs, el('div', 'empty-state dim', 'Certificates are not part of the mock. Use client secrets below.'));

    const sec = add(pane, el('section', 'section'));
    const head = add(sec, el('div'));
    head.style.display = 'flex';
    head.style.alignItems = 'center';
    head.style.gap = '12px';
    add(head, el('h2', null, 'Client secrets'));
    const spacer = add(head, el('span'));
    spacer.style.flex = '1';
    const newBtn = add(head, el('button', 'cmd'));
    newBtn.type = 'button';
    newBtn.appendChild(icon('key'));
    add(newBtn, el('span', null, 'New client secret'));
    newBtn.addEventListener('click', () => newSecret(app));
    add(sec, el('p', 'note',
      'A registered secret is enforced at the token endpoint: the app must then present a matching value (AADSTS7000215). ' +
      'The real Entra shows a secret value exactly once; this mock also keeps it here (reveal), since everything is in-memory dev state.'));

    const wrap = add(sec, el('div', 'table-wrap'));
    const table = add(wrap, el('table', 'list'));
    const hr = add(add(table, el('thead')), el('tr'));
    for (const h of ['Description', 'Value', 'Secret ID', 'Expires', '']) add(hr, el('th', null, h));
    const body = add(table, el('tbody'));
    const secrets = app.secrets || [];
    if (!secrets.length) {
      const td = add(add(body, el('tr')), el('td'));
      td.colSpan = 5;
      add(td, el('div', 'empty-state', 'No client secrets. The app authenticates with any secret (mock default).'));
    }
    for (const s of secrets) {
      const tr = add(body, el('tr'));
      add(tr, el('td', null, s.description || '—'));
      const vTd = add(tr, el('td'));
      add(vTd, el('span', 'mono', revealed.has(s.id) ? s.value : '••••••••••••••••'));
      const eye = add(vTd, iconBtn('eye', revealed.has(s.id) ? 'Hide value' : 'Reveal value (mock)'));
      eye.addEventListener('click', () => {
        if (revealed.has(s.id)) revealed.delete(s.id);
        else revealed.add(s.id);
        render();
      });
      const idTd = add(tr, el('td'));
      add(idTd, el('span', 'mono', s.id));
      idTd.appendChild(copyBtn(() => s.id));
      const expTd = add(tr, el('td'));
      add(expTd, el('span', expired(s.expires) ? 'pill expired' : null, fmtDate(s.expires)));
      if (expired(s.expires)) add(expTd, el('span', null, ' (expired)'));
      const act = add(tr, el('td'));
      add(act, iconBtn('trash', 'Delete secret', true)).addEventListener('click', () => {
        confirmModal('Delete client secret',
          'Delete the secret "' + (s.description || s.id) + '"? Presenting it stops working immediately.',
          async () => {
            try {
              await api('entra/apps/' + encodeURIComponent(app.clientId) + '/secrets/' + encodeURIComponent(s.id), DEL);
              toast('Successfully deleted the client secret');
              await reload();
              render();
            } catch (err) { toast(err.message, true); }
          });
      });
    }
  }

  function newSecret(app) {
    let desc, expires;
    openModal({
      title: 'Add client secret',
      body: (pane) => {
        const f1 = add(pane, el('div', 'field'));
        add(f1, el('label', null, 'Description')).setAttribute('for', 'sec-desc');
        desc = add(f1, el('input'));
        desc.type = 'text';
        desc.id = 'sec-desc';
        desc.placeholder = 'e.g. iam-sync production';
        const f2 = add(pane, el('div', 'field'));
        add(f2, el('label', null, 'Expires')).setAttribute('for', 'sec-exp');
        expires = add(f2, el('select'));
        expires.id = 'sec-exp';
        for (const [v, l] of [['6m', '6 months'], ['12m', '12 months'], ['24m', '24 months']]) {
          add(expires, el('option', null, l)).value = v;
        }
      },
      actions: [{
        label: 'Add', primary: true, onClick: async (close) => {
          try {
            const sec = await api('entra/apps/' + encodeURIComponent(app.clientId) + '/secrets',
              POSTJSON({ description: desc.value.trim(), expires: expires.value }));
            close();
            await reload();
            render();
            showSecretValue(sec);
          } catch (err) { toast(err.message, true); }
        }
      }]
    });
  }

  function showSecretValue(sec) {
    openModal({
      title: 'New client secret created',
      body: (pane) => {
        const warn = add(pane, el('div', 'infobar warn'));
        warn.appendChild(icon('info'));
        add(warn, el('span', null,
          'Copy this value now. The real Entra admin center never shows it again; this mock keeps it in Certificates & secrets (reveal).'));
        const kv = (label, value, copy) => {
          const dl = add(pane, el('dl', 'kv'));
          add(dl, el('dt', null, label));
          const dd = add(dl, el('dd'));
          add(dd, el('span', 'mono', value));
          if (copy) dd.appendChild(copyBtn(() => value));
        };
        kv('Description', sec.description || '—');
        kv('Value', sec.value, true);
        kv('Secret ID', sec.id, true);
        kv('Expires', fmtDate(sec.expires));
      }
    });
  }

  /* --- App roles --- */

  function drawRoles(pane, app) {
    const local = structuredClone(app);
    const bar = saveBar(pane, app, () => local);
    const mark = bar.mark;

    const sec = add(pane, el('section', 'section'));
    add(sec, el('h2', null, 'App roles'));
    add(sec, el('p', 'note',
      "App roles are emitted as the roles claim of this app's app-only (client credentials) access tokens."));

    const list = add(sec, el('div', 'rowlist'));
    function drawList() {
      list.replaceChildren();
      local.roles = local.roles || [];
      if (!local.roles.length) add(list, el('div', 'rowitem dim', 'No app roles.'));
      for (const role of local.roles) {
        const item = add(list, el('div', 'rowitem'));
        const input = ghostInput();
        input.classList.add('grow');
        input.value = role;
        input.placeholder = 'e.g. Directory.Read.All';
        input.addEventListener('input', () => {
          local.roles[local.roles.indexOf(role)] = input.value.trim();
          mark();
        });
        item.appendChild(input);
        add(item, iconBtn('x', 'Remove app role', true)).addEventListener('click', () => {
          local.roles = local.roles.filter((r) => r !== role);
          mark();
          drawList();
        });
      }
      const addRowEl = add(list, el('div', 'rowadd'));
      const inp = add(addRowEl, el('input'));
      inp.type = 'text';
      inp.placeholder = 'Add an app role value…';
      const btn = add(addRowEl, el('button', 'cmd', 'Add role'));
      btn.type = 'button';
      const doAdd = () => {
        const v = inp.value.trim();
        if (!v) return;
        local.roles.push(v);
        mark();
        drawList();
      };
      btn.addEventListener('click', doAdd);
      inp.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); doAdd(); } });
    }
    drawList();
  }

  /* --- Token configuration --- */

  function drawTokenConfig(pane, app) {
    const local = structuredClone(app);
    const bar = saveBar(pane, app, () => local);
    const mark = bar.mark;

    const sec = add(pane, el('section', 'section'));
    add(sec, el('h2', null, 'Token configuration'));
    add(sec, el('p', 'note',
      'Claims mappings are added to the ID tokens issued to this app, the way an Entra claims-mapping policy does. ' +
      'Reserved claims (sub, tid, oid, groups, …) cannot be mapped.'));

    const list = add(sec, el('div', 'rowlist'));
    function drawList() {
      list.replaceChildren();
      local.claims = local.claims || [];
      if (!local.claims.length) add(list, el('div', 'rowitem dim', 'No claims mappings.'));
      for (const c of local.claims) {
        const item = add(list, el('div', 'rowitem'));
        const name = ghostInput();
        name.value = c.name;
        name.placeholder = 'Claim name, e.g. department';
        name.style.width = '220px';
        name.style.flex = 'none';
        name.addEventListener('input', () => { c.name = name.value.trim(); mark(); });
        item.appendChild(name);
        add(item, el('span', 'dim', '←'));
        const source = add(item, el('select'));
        source.style.width = '240px';
        source.style.flex = 'none';
        for (const s of CLAIM_SOURCES) {
          const o = add(source, el('option', null, s));
          o.value = s;
          if (s === (c.source || '').toLowerCase()) o.selected = true;
        }
        source.addEventListener('change', () => { c.source = source.value; mark(); });
        add(item, iconBtn('x', 'Remove claim', true)).addEventListener('click', () => {
          local.claims = local.claims.filter((m) => m !== c);
          mark();
          drawList();
        });
      }
      const addRowEl = add(list, el('div', 'rowadd'));
      const inp = add(addRowEl, el('input'));
      inp.type = 'text';
      inp.placeholder = 'New claim name…';
      inp.style.width = '220px';
      inp.style.flex = 'none';
      const sel = add(addRowEl, el('select'));
      sel.style.width = '240px';
      sel.style.flex = 'none';
      for (const s of CLAIM_SOURCES) add(sel, el('option', null, s)).value = s;
      const btn = add(addRowEl, el('button', 'cmd', 'Add claim'));
      btn.type = 'button';
      const doAdd = () => {
        const v = inp.value.trim();
        if (!v) return;
        local.claims.push({ name: v, source: sel.value });
        mark();
        drawList();
      };
      btn.addEventListener('click', doAdd);
      inp.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); doAdd(); } });
    }
    drawList();
  }

  /* ===== boot ===== */

  function initNav() {
    $('#nav-toggle').addEventListener('click', () => $('#blade').classList.toggle('collapsed'));
    for (const group of document.querySelectorAll('.nav-group[data-group]')) {
      group.addEventListener('click', () => {
        const open = group.getAttribute('aria-expanded') === 'true';
        group.setAttribute('aria-expanded', String(!open));
        const items = document.querySelector('[data-group-items="' + group.dataset.group + '"]');
        if (items) items.classList.toggle('hidden', open);
      });
    }
  }

  window.addEventListener('hashchange', render);
  window.addEventListener('DOMContentLoaded', () => {
    initNav();
    render();
  });
})();
