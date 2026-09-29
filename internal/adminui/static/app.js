/* mock-oidc admin — dependency-free SPA over /admin/api. Same GitHub Primer
   design language as ai-gateway's admin UI. The strict CSP bans inline
   script, so everything runs from this file; all dynamic text is set with
   textContent (no innerHTML anywhere). */
(() => {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  /* ===== Octicons (16, fill=currentColor) ===== */

  const OCT = {
    sun: 'M8 12a4 4 0 1 1 0-8 4 4 0 0 1 0 8Zm0-1.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM8 0a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0V.75A.75.75 0 0 1 8 0Zm0 13a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 8 13ZM2.343 2.343a.75.75 0 0 1 1.061 0l1.06 1.061a.75.75 0 1 1-1.06 1.06l-1.06-1.06a.75.75 0 0 1 0-1.06Zm9.193 9.193a.75.75 0 0 1 1.06 0l1.061 1.06a.75.75 0 0 1-1.06 1.061l-1.061-1.06a.75.75 0 0 1 0-1.061ZM16 8a.75.75 0 0 1-.75.75h-1.5a.75.75 0 0 1 0-1.5h1.5A.75.75 0 0 1 16 8ZM3 8a.75.75 0 0 1-.75.75H.75a.75.75 0 0 1 0-1.5h1.5A.75.75 0 0 1 3 8Zm10.657-5.657a.75.75 0 0 1 0 1.06l-1.061 1.061a.75.75 0 1 1-1.06-1.06l1.06-1.061a.75.75 0 0 1 1.06 0Zm-9.193 9.193a.75.75 0 0 1 0 1.06l-1.06 1.061a.75.75 0 0 1-1.061-1.06l1.06-1.061a.75.75 0 0 1 1.061 0Z',
    moon: 'M9.598 1.591a.749.749 0 0 1 .785-.175 7.001 7.001 0 1 1-8.967 8.967.75.75 0 0 1 .961-.96 5.5 5.5 0 0 0 7.046-7.046.75.75 0 0 1 .175-.786Zm1.616 1.945a7 7 0 0 1-7.678 7.678 5.499 5.499 0 1 0 7.678-7.678Z',
    sync: 'M1.705 8.005a.75.75 0 0 1 .834.656 5.5 5.5 0 0 0 9.592 2.97l-1.204-1.204a.25.25 0 0 1 .177-.427h3.646a.25.25 0 0 1 .25.25v3.646a.25.25 0 0 1-.427.177l-1.38-1.38A7.002 7.002 0 0 1 1.05 8.84a.75.75 0 0 1 .656-.834ZM8 2.5a5.487 5.487 0 0 0-4.131 1.869l1.204 1.204A.25.25 0 0 1 4.896 6H1.25A.25.25 0 0 1 1 5.75V2.104a.25.25 0 0 1 .427-.177l1.38 1.38A7.002 7.002 0 0 1 14.95 7.16a.75.75 0 0 1-1.49.178A5.5 5.5 0 0 0 8 2.5Z',
    trash: 'M11 1.75V3h2.25a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75ZM4.496 6.675l.66 6.6a.25.25 0 0 0 .249.225h5.19a.25.25 0 0 0 .249-.225l.66-6.6a.75.75 0 0 1 1.492.149l-.66 6.6A1.748 1.748 0 0 1 10.595 15h-5.19a1.75 1.75 0 0 1-1.741-1.575l-.66-6.6a.75.75 0 1 1 1.492-.15ZM6.5 1.75V3h3V1.75a.25.25 0 0 0-.25-.25h-2.5a.25.25 0 0 0-.25.25Z',
    check: 'M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z',
    x: 'M3.72 3.72a.75.75 0 0 1 1.06 0L8 6.94l3.22-3.22a.749.749 0 0 1 1.275.326.749.749 0 0 1-.215.734L9.06 8l3.22 3.22a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215L8 9.06l-3.22 3.22a.751.751 0 0 1-1.042-.018.751.751 0 0 1-.018-1.042L6.94 8 3.72 4.78a.75.75 0 0 1 0-1.06Z',
    pencil: 'M11.013 1.427a1.75 1.75 0 0 1 2.474 0l1.086 1.086a1.75 1.75 0 0 1 0 2.474l-8.61 8.61c-.21.21-.47.364-.756.445l-3.251.93a.75.75 0 0 1-.927-.928l.929-3.25c.081-.286.235-.547.445-.758l8.61-8.61Zm.176 4.823L9.75 4.81l-6.286 6.287a.253.253 0 0 0-.064.108l-.558 1.953 1.953-.558a.253.253 0 0 0 .108-.064Zm1.238-3.763a.25.25 0 0 0-.354 0L10.811 3.75l1.439 1.44 1.263-1.263a.25.25 0 0 0 0-.354Z',
    plus: 'M7.75 2a.75.75 0 0 1 .75.75V7h4.25a.75.75 0 0 1 0 1.5H8.5v4.25a.75.75 0 0 1-1.5 0V8.5H2.75a.75.75 0 0 1 0-1.5H7V2.75A.75.75 0 0 1 7.75 2Z'
  };

  function octo(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('fill', 'currentColor');
    svg.setAttribute('aria-hidden', 'true');
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    p.setAttribute('d', OCT[name]);
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
  function chip(cls, text, title) {
    const c = el('span', 'chip ' + cls, text);
    if (title) c.title = title;
    return c;
  }
  function boolChip(on, onText, offText) {
    return chip(on ? 'chip-on' : 'chip-off', on ? onText : offText);
  }
  function csv(v) { return (v || []).join(', '); }
  function parseCsv(s) {
    return (s || '').split(',').map((x) => x.trim()).filter(Boolean);
  }
  function iconBtn(icon, title, danger) {
    const b = el('button', 'btn btn-sm icon-btn' + (danger ? ' btn-danger' : ''));
    b.type = 'button';
    b.title = title;
    b.setAttribute('aria-label', title);
    b.appendChild(octo(icon));
    return b;
  }

  /* ===== theme ===== */

  const THEME_KEY = 'mockoidc_theme';

  function pinnedTheme() { return localStorage.getItem(THEME_KEY); }
  function isDark() {
    const pinned = pinnedTheme();
    if (pinned) return pinned === 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  function drawThemeIcon() {
    $('#theme-toggle').replaceChildren(octo(isDark() ? 'sun' : 'moon'));
  }
  function initTheme() {
    const pinned = pinnedTheme();
    if (pinned) document.documentElement.dataset.theme = pinned;
    drawThemeIcon();
    $('#theme-toggle').addEventListener('click', () => {
      const next = isDark() ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      localStorage.setItem(THEME_KEY, next);
      drawThemeIcon();
    });
  }

  /* ===== API ===== */

  async function api(path, opts) {
    const res = await fetch('/admin/api/' + path, opts);
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try {
        const doc = await res.json();
        if (doc && doc.error) msg = doc.error;
      } catch (e) { /* keep status message */ }
      throw new Error(msg);
    }
    return res.json();
  }
  const POST = { method: 'POST' };
  const DEL = { method: 'DELETE' };
  function PUT(body) {
    return { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  }
  function POSTJSON(body) {
    return { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  }

  /* ===== toast ===== */

  let toastTimer = null;
  function toast(msg, isError) {
    const t = $('#toast');
    t.classList.toggle('toast-error', !!isError);
    const icon = el('div', 'toast-icon');
    icon.appendChild(octo(isError ? 'x' : 'check'));
    t.replaceChildren(icon, el('div', 'toast-msg', msg));
    t.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add('hidden'), 4000);
  }

  /* ===== drawer ===== */

  // fields: {name, label, type: text|number|select|checkbox|csv, value,
  //          options:[{value,label}], placeholder, help, disabled, wide}
  function openDrawer(title, fields, saveLabel, onSave) {
    const root = $('#drawer-root');
    const backdrop = el('div', 'drawer-backdrop');
    const drawer = el('div', 'drawer');
    root.replaceChildren(backdrop, drawer);
    const close = () => root.replaceChildren();
    backdrop.addEventListener('click', close);

    add(drawer, el('h2', null, title));
    const form = add(drawer, el('form'));
    const inputs = {};
    const errBox = add(drawer, el('div', 'error hidden'));

    for (const f of fields) {
      const wrap = el('div', f.wide ? 'full' : '');
      form.appendChild(wrap);
      if (f.type === 'checkbox') {
        const lab = add(wrap, el('label', null));
        lab.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:14px;font-weight:400;cursor:pointer';
        const cb = el('input');
        cb.type = 'checkbox';
        cb.checked = !!f.value;
        if (f.disabled) cb.disabled = true;
        lab.appendChild(cb);
        lab.appendChild(document.createTextNode(f.label));
        inputs[f.name] = cb;
      } else {
        add(wrap, el('label', null, f.label));
        let input;
        if (f.type === 'select') {
          input = el('select');
          for (const opt of f.options) {
            const o = el('option', null, opt.label);
            o.value = opt.value;
            input.appendChild(o);
          }
          input.value = f.value;
        } else {
          input = el('input');
          if (f.type === 'number') input.type = 'number';
          else input.type = 'text';
          if (f.value != null) input.value = f.type === 'csv' ? csv(f.value) : f.value;
          if (f.placeholder) input.placeholder = f.placeholder;
        }
        if (f.disabled) input.disabled = true;
        wrap.appendChild(input);
        if (f.help) add(wrap, el('div', 'help', f.help));
        inputs[f.name] = input;
      }
    }

    const actions = add(drawer, el('div', 'drawer-actions'));
    const cancel = add(actions, el('button', 'btn', 'Cancel'));
    cancel.type = 'button';
    cancel.addEventListener('click', close);
    const save = add(actions, el('button', 'btn btn-primary', saveLabel));
    save.type = 'submit';

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const values = {};
      for (const f of fields) {
        const node = inputs[f.name];
        if (f.type === 'checkbox') values[f.name] = node.checked;
        else if (f.type === 'csv') values[f.name] = parseCsv(node.value);
        else if (f.type === 'number') values[f.name] = node.value ? Number(node.value) : 0;
        else values[f.name] = node.value;
      }
      save.disabled = true;
      errBox.classList.add('hidden');
      try {
        await onSave(values);
        close();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
        save.disabled = false;
      }
    });
    drawer.querySelector('input,select') && drawer.querySelector('input,select').focus();
  }

  /* ===== state ===== */

  let overview = null;
  let settings = null;
  let entra = null;
  let directory = null;
  let directoryOn = false;

  const ROUTES = ['overview', 'entra', 'directory'];

  function currentRoute() {
    const h = decodeURIComponent(location.hash.replace(/^#\/?/, ''));
    return ROUTES.includes(h) ? h : 'overview';
  }

  function render() {
    const route = currentRoute();
    document.querySelectorAll('#nav a').forEach((a) => {
      a.classList.toggle('active', a.dataset.route === route);
    });
    const view = $('#view');
    view.replaceChildren();
    if (route === 'entra' && entra) drawEntra(view);
    else if (route === 'directory') drawDirectory(view);
    else drawOverview(view);
  }

  async function refresh() {
    overview = null; settings = null; entra = null; directory = null;
    try {
      overview = await api('overview');
      $('#health').className = 'health dot-on';
    } catch (err) {
      $('#health').className = 'health dot-off';
      $('#view').replaceChildren(el('div', 'error', 'Admin API unreachable: ' + err.message));
      return;
    }
    try { settings = await api('settings'); } catch (e) { settings = null; }
    if (overview.entraConfigured) {
      try { entra = await api('entra'); } catch (e) { entra = null; }
    }
    $('#nav a[data-route="entra"]').classList.toggle('hidden', !entra);
    directoryOn = false;
    try {
      directory = await api('directory');
      directoryOn = true;
    } catch (e) { directory = null; }
    render();
  }

  async function reload(route) {
    try {
      overview = await api('overview');
      try { settings = await api('settings'); } catch (e) { settings = null; }
      if (overview.entraConfigured) {
        try { entra = await api('entra'); } catch (e) { entra = null; }
      } else {
        entra = null;
      }
      if (directoryOn) {
        try { directory = await api('directory'); } catch (e) { directory = null; }
      }
      $('#health').className = 'health dot-on';
    } catch (err) {
      toast(err.message, true);
      return;
    }
    render();
  }

  /* ===== overview view ===== */

  function drawOverview(view) {
    add(view, el('h1', null, 'Overview'));
    add(view, el('p', 'facts', 'Any /{issuerId} path prefix is a valid issuer; the URLs below use this request\'s origin.'));
    if (!overview) return;

    const entraOn = settings ? settings.entraEnabled : overview.entraConfigured && !!entra;
    const cards = add(view, el('div', 'cards'));
    card(cards, 'Entra mode', entraOn ? 'enabled' : 'off');
    card(cards, 'Entra tenants', entra ? String(entra.tenants.length) : '—');
    card(cards, 'Entra users', entra ? String(entra.users.length) : '—');
    card(cards, 'Directory users', overview.directoryUsers != null ? String(overview.directoryUsers) : '—');

    drawSettings(view);
    drawEndpoints(view);
  }

  function card(parent, label, value) {
    const c = add(parent, el('div', 'card'));
    add(c, el('div', 'label', label));
    add(c, el('div', 'value', value != null ? value : ''));
  }

  function drawSettings(view) {
    add(view, el('h2', null, 'Settings'));
    const panel = add(view, el('div', 'panel'));
    if (!settings) {
      add(panel, el('p', 'dim', 'Runtime settings are not available on this instance.'));
      return;
    }
    settingRow(panel, 'Interactive login',
      'Show the login page on /authorize (prompt=login always shows it).',
      settings.interactiveLogin, false, async (v) => {
        await api('settings', POSTJSON({ name: 'interactiveLogin', value: v }));
      });
    settingRow(panel, 'Rotate refresh token',
      'Refresh grants mint a new refresh_token and invalidate the old one.',
      settings.rotateRefreshToken, false, async (v) => {
        await api('settings', POSTJSON({ name: 'rotateRefreshToken', value: v }));
      });
    settingRow(panel, 'Entra mode',
      'Serve the /' + (entra ? entra.basePath : 'entra') + '/ endpoints. Turning it off answers them like unrouted paths (405).',
      settings.entraEnabled, !settings.entraConfigured, async (v) => {
        await api('settings', POSTJSON({ name: 'entra', value: v }));
      });
  }

  function settingRow(parent, label, desc, value, disabled, apply) {
    const row = add(parent, el('div', 'setting-row'));
    const text = add(row, el('div', 'setting-text'));
    add(text, el('div', null, label));
    add(text, el('div', 'desc', desc + (disabled ? ' — requires entra config at startup.' : '')));
    const sw = add(row, el('label', 'switch'));
    const cb = el('input');
    cb.type = 'checkbox';
    cb.checked = value;
    cb.disabled = disabled;
    sw.appendChild(cb);
    sw.appendChild(el('span', 'track'));
    sw.appendChild(el('span', 'switch-label', value ? 'on' : 'off'));
    cb.addEventListener('change', async () => {
      const next = cb.checked;
      if (label === 'Entra mode' && !next &&
        !window.confirm('Turn Entra mode off? The /entra endpoints stop serving until turned back on.')) {
        cb.checked = !next;
        return;
      }
      try {
        await apply(next);
        toast(label + ' ' + (next ? 'enabled' : 'disabled'));
        await reload();
      } catch (err) {
        cb.checked = !next;
        toast(err.message, true);
      }
    });
  }

  function drawEndpoints(view) {
    add(view, el('h2', null, 'Endpoints'));
    const issuers = [{ id: '', label: 'root issuer' }].concat(
      (overview.tokenCallbacks || []).map((cb) => ({ id: cb.issuerId, label: 'issuer ' + cb.issuerId })));
    const eps = [
      ['Issuer URL', (b) => b],
      ['Discovery', (b) => b + '/.well-known/openid-configuration'],
      ['Authorization', (b) => b + '/authorize'],
      ['Token', (b) => b + '/token'],
      ['UserInfo', (b) => b + '/userinfo'],
      ['Introspection', (b) => b + '/introspect'],
      ['Revocation', (b) => b + '/revoke'],
      ['End session', (b) => b + '/endsession'],
      ['JWKS', (b) => b + '/jwks']
    ];
    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    add(hr, el('th', null, 'Endpoint'));
    for (const iss of issuers) add(hr, el('th', null, iss.label));
    const tbody = add(table, el('tbody'));
    for (const [name, url] of eps) {
      const tr = add(tbody, el('tr'));
      add(tr, el('td', null, name));
      for (const iss of issuers) {
        const td = add(tr, el('td'));
        const base = location.origin + (iss.id ? '/' + iss.id : '');
        const a = add(td, el('a', 'mono', url(base)));
        a.href = url(base);
        a.target = '_blank';
        a.rel = 'noopener';
      }
    }
  }

  /* ===== entra view ===== */

  function drawEntra(view) {
    add(view, el('h1', null, 'Entra mode'));
    add(view, el('p', 'facts', 'basePath /' + entra.basePath + ' · token expiry ' +
      entra.tokenExpiry + 's · default group limit ' + entra.defaultGroupLimit +
      ' · edits are in-memory; "Reset to config" restores the config file.'));

    const cards = add(view, el('div', 'cards'));
    card(cards, 'Tenants', String(entra.tenants.length));
    card(cards, 'Users', String(entra.users.length));
    card(cards, 'Consents', String(entra.consents.length));
    card(cards, 'Active kid', entra.keys.activeKid);

    drawTenants(view);
    drawUsers(view);
    drawConsents(view);
    drawKeys(view);
  }

  function sectionHead(view, title, btnLabel, onClick, btnIcon) {
    const head = add(view, el('div', 'section-head'));
    add(head, el('h2', null, title));
    if (btnLabel) {
      const b = add(head, el('button', 'btn btn-sm'));
      b.type = 'button';
      b.appendChild(octo(btnIcon || 'plus'));
      b.appendChild(document.createTextNode(' ' + btnLabel));
      b.addEventListener('click', onClick);
    }
    return head;
  }

  function drawTenants(view) {
    sectionHead(view, 'Tenants', 'New tenant', () => tenantDrawer(null), 'plus');
    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    for (const h of ['tid', 'Name', 'Domains', 'Group claim', 'Group limit', 'Consent required', '']) {
      add(hr, el('th', null, h));
    }
    const tbody = add(table, el('tbody'));
    for (const t of entra.tenants) {
      const tr = add(tbody, el('tr'));
      add(tr, el('td', 'mono', t.tid));
      add(tr, el('td', null, t.name));
      add(tr, el('td', null, (t.domains || []).join(', ') || '—'));
      const fmtTd = add(tr, el('td'));
      fmtTd.appendChild(chip('chip-accent', t.groupClaimFormat));
      add(tr, el('td', 'num', String(t.groupLimit)));
      const crTd = add(tr, el('td'));
      crTd.appendChild(boolChip(t.consentRequired, 'required', 'not required'));
      const act = add(tr, el('td'));
      act.style.textAlign = 'right';
      const actions = add(act, el('div', 'row-actions'));
      const edit = add(actions, iconBtn('pencil', 'Edit tenant'));
      edit.addEventListener('click', () => tenantDrawer(t));
      const del = add(actions, iconBtn('trash', 'Delete tenant (cascades users and consents)', true));
      del.addEventListener('click', async () => {
        if (!window.confirm('Delete tenant ' + t.name + ' (' + t.tid + ')?\nIts users (' +
          entra.users.filter((u) => u.tid === t.tid).length + ') and consents are deleted with it.')) return;
        try {
          await api('entra/tenants/' + t.tid, DEL);
          toast('Tenant deleted');
          await reload();
        } catch (err) { toast(err.message, true); }
      });
    }
  }

  function tenantDrawer(t) {
    const isNew = !t;
    openDrawer(isNew ? 'New tenant' : 'Edit tenant', [
      { name: 'tid', label: 'Tenant ID (GUID)', type: 'text', value: t && t.tid, disabled: !isNew,
        placeholder: 'e.g. 44444444-4444-4444-4444-444444444444', wide: true },
      { name: 'name', label: 'Name', type: 'text', value: t && t.name, placeholder: 'defaults to the tid' },
      { name: 'domains', label: 'Domains', type: 'csv', value: t && t.domains, placeholder: 'a.test, b.test', wide: true },
      { name: 'groupClaimFormat', label: 'Group claim format', type: 'select', value: t ? t.groupClaimFormat : 'name',
        options: [{ value: 'name', label: 'name' }, { value: 'object_id', label: 'object_id' }] },
      { name: 'groupLimit', label: 'Group limit', type: 'number', value: t ? t.groupLimit : entra.defaultGroupLimit },
      { name: 'consentRequired', label: 'Admin consent required', type: 'checkbox', value: t && t.consentRequired, wide: true }
    ], isNew ? 'Create tenant' : 'Save', async (v) => {
      if (isNew) await api('entra/tenants', POSTJSON(v));
      else await api('entra/tenants/' + t.tid, PUT(v));
      toast(isNew ? 'Tenant created' : 'Tenant saved');
      await reload();
    });
  }

  function drawUsers(view) {
    sectionHead(view, 'Users', 'New user', () => userDrawer(null), 'plus');
    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    for (const h of ['Username', 'Tenant', 'Name', 'Email', 'Groups', 'AMR', 'Admin', 'Error injection', '']) {
      add(hr, el('th', null, h));
    }
    const tbody = add(table, el('tbody'));
    for (const u of entra.users) {
      const tr = add(tbody, el('tr'));
      add(tr, el('td', 'mono', u.username));
      add(tr, el('td', 'mono', u.tid));
      add(tr, el('td', null, u.name));
      add(tr, el('td', null, u.email || '—'));
      const gTd = add(tr, el('td', 'num', String((u.groups || []).length)));
      gTd.title = (u.groups || []).join('\n');
      const amrTd = add(tr, el('td'));
      for (const a of u.amr || []) amrTd.appendChild(chip('chip-done', a));
      if (!(u.amr || []).length) add(amrTd, el('span', 'dim', '—'));
      const adTd = add(tr, el('td'));
      if (u.admin) adTd.appendChild(chip('chip-on', 'admin'));
      else add(adTd, el('span', 'dim', '—'));
      const errTd = add(tr, el('td'));
      if (u.error) errTd.appendChild(chip('chip-attention', u.error));
      else add(errTd, el('span', 'dim', '—'));
      const act = add(tr, el('td'));
      act.style.textAlign = 'right';
      const actions = add(act, el('div', 'row-actions'));
      const edit = add(actions, iconBtn('pencil', 'Edit user'));
      edit.addEventListener('click', () => userDrawer(u));
      const del = add(actions, iconBtn('trash', 'Delete user', true));
      del.addEventListener('click', async () => {
        if (!window.confirm('Delete user ' + u.username + ' from tenant ' + u.tid + '?')) return;
        try {
          await api('entra/users/' + u.tid + '/' + encodeURIComponent(u.username), DEL);
          toast('User deleted');
          await reload();
        } catch (err) { toast(err.message, true); }
      });
    }
    if (!entra.users.length) add(view, el('div', 'empty', 'No users configured.'));
  }

  function userDrawer(u) {
    const isNew = !u;
    const tenantOpts = entra.tenants.map((t) => ({ value: t.tid, label: t.name + ' (' + t.tid + ')' }));
    const errOpts = [
      { value: '', label: 'none' },
      { value: 'interaction_required', label: 'interaction_required' },
      { value: 'access_denied', label: 'access_denied' },
      { value: 'invalid_grant', label: 'invalid_grant (disabled)' }
    ];
    openDrawer(isNew ? 'New user' : 'Edit user', [
      { name: 'username', label: 'Username', type: 'text', value: u && u.username, disabled: !isNew, wide: true },
      { name: 'tid', label: 'Tenant', type: 'select', value: u ? u.tid : (tenantOpts[0] && tenantOpts[0].value),
        options: tenantOpts, disabled: !isNew, wide: true },
      { name: 'name', label: 'Name', type: 'text', value: u && u.name, placeholder: 'defaults to the username' },
      { name: 'email', label: 'Email', type: 'text', value: u && u.email },
      { name: 'groups', label: 'Groups', type: 'csv', value: u && u.groups, placeholder: 'team-a, team-b', wide: true },
      { name: 'amr', label: 'AMR', type: 'csv', value: u && u.amr, placeholder: 'pwd, mfa', wide: true },
      { name: 'admin', label: 'Admin (may grant admin consent)', type: 'checkbox', value: u && u.admin },
      { name: 'error', label: 'Error injection', type: 'select', value: u ? u.error : '', options: errOpts }
    ], isNew ? 'Create user' : 'Save', async (v) => {
      if (isNew) await api('entra/users', POSTJSON(v));
      else await api('entra/users/' + u.tid + '/' + encodeURIComponent(u.username), PUT(v));
      toast(isNew ? 'User created' : 'User saved');
      await reload();
    });
  }

  function drawConsents(view) {
    sectionHead(view, 'Consents', null);
    const bar = add(view, el('div', 'toolbar'));
    const reset = add(bar, el('button', 'btn btn-sm btn-danger'));
    reset.type = 'button';
    reset.appendChild(octo('trash'));
    reset.appendChild(document.createTextNode(' Reset to config'));
    reset.title = 'Restore tenants, users and consents to the config file';
    reset.addEventListener('click', async () => {
      if (!window.confirm('Reset Entra state to the config seed? Runtime tenants, users and consent grants are discarded (signing keys are kept).')) return;
      try {
        await api('entra/reset', POST);
        toast('Entra state reset to config');
        await reload();
      } catch (err) { toast(err.message, true); }
    });
    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    add(hr, el('th', null, 'Client ID'));
    add(hr, el('th', null, 'Tenant'));
    add(hr, el('th', null, ''));
    const tbody = add(table, el('tbody'));
    for (const c of entra.consents) {
      const tr = add(tbody, el('tr'));
      add(tr, el('td', 'mono', c.clientId));
      add(tr, el('td', 'mono', c.tid));
      const act = add(tr, el('td'));
      act.style.textAlign = 'right';
      const del = add(act, iconBtn('trash', 'Revoke consent', true));
      del.addEventListener('click', async () => {
        try {
          await api('entra/consents/' + encodeURIComponent(c.clientId) + '/' + c.tid, DEL);
          toast('Consent revoked');
          await reload();
        } catch (err) { toast(err.message, true); }
      });
    }
    if (!entra.consents.length) add(view, el('div', 'empty', 'No consents granted.'));
  }

  function drawKeys(view) {
    sectionHead(view, 'Signing keys', null);
    const panel = add(view, el('div', 'panel'));
    const bar = add(panel, el('div', 'toolbar'));
    const rotate = add(bar, el('button', 'btn btn-sm'));
    rotate.type = 'button';
    rotate.appendChild(octo('sync'));
    rotate.appendChild(document.createTextNode(' Rotate keys'));
    rotate.addEventListener('click', async () => {
      if (!window.confirm('Rotate the Entra signing keys? The previous key stays published for verification.')) return;
      try {
        const out = await api('entra/rotate-keys', POST);
        toast('Rotated signing keys; new kid ' + out.kid);
        await reload();
      } catch (err) { toast(err.message, true); }
    });
    const kids = add(bar, el('span'));
    kids.appendChild(el('span', 'dim', 'published kids: '));
    (entra.keys.publishedKids || []).forEach((kid) => {
      const c = chip(kid === entra.keys.activeKid ? 'chip-on' : '', kid);
      if (kid === entra.keys.activeKid) c.title = 'active signing key';
      kids.appendChild(c);
    });
  }

  /* ===== directory view ===== */

  function drawDirectory(view) {
    add(view, el('h1', null, 'Login directory'));
    if (!directory) {
      add(view, el('p', 'facts', 'The navikt login page quick-picks come from a directory seeded via USER_DIRECTORY_PATH (demo-users.json).'));
      add(view, el('div', 'empty', 'No directory configured on this instance (USER_DIRECTORY_PATH not set). The login page shows its manual form.'));
      return;
    }
    add(view, el('p', 'facts', 'Users offered as quick-picks on the login page. The server still accepts any username — this list only feeds the picker. Seeded from demo-users.json.'));

    sectionHead(view, 'Users', 'New user', () => directoryDrawer(null), 'plus');
    const bar = add(view, el('div', 'toolbar'));
    const reset = add(bar, el('button', 'btn btn-sm btn-danger'));
    reset.type = 'button';
    reset.appendChild(octo('trash'));
    reset.appendChild(document.createTextNode(' Reset to file'));
    reset.addEventListener('click', async () => {
      if (!window.confirm('Reset the directory to the seed file (demo-users.json)?')) return;
      try {
        await api('directory/reset', POST);
        toast('Directory reset to file');
        await reload();
      } catch (err) { toast(err.message, true); }
    });

    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    for (const h of ['Username', 'Name', 'Email', 'Groups', '']) add(hr, el('th', null, h));
    const tbody = add(table, el('tbody'));
    for (const u of directory) {
      const tr = add(tbody, el('tr'));
      add(tr, el('td', 'mono', u.username));
      add(tr, el('td', null, u.name));
      add(tr, el('td', null, u.email || '—'));
      add(tr, el('td', null, (u.groups || []).join(', ') || '—'));
      const act = add(tr, el('td'));
      act.style.textAlign = 'right';
      const actions = add(act, el('div', 'row-actions'));
      const edit = add(actions, iconBtn('pencil', 'Edit user'));
      edit.addEventListener('click', () => directoryDrawer(u));
      const del = add(actions, iconBtn('trash', 'Delete user', true));
      del.addEventListener('click', async () => {
        if (!window.confirm('Remove ' + u.username + ' from the login directory?')) return;
        try {
          await api('directory/users/' + encodeURIComponent(u.username), DEL);
          toast('User removed');
          await reload();
        } catch (err) { toast(err.message, true); }
      });
    }
    if (!directory.length) add(view, el('div', 'empty', 'The directory is empty.'));
  }

  function directoryDrawer(u) {
    const isNew = !u;
    openDrawer(isNew ? 'New directory user' : 'Edit directory user', [
      { name: 'username', label: 'Username', type: 'text', value: u && u.username, disabled: !isNew, wide: true },
      { name: 'name', label: 'Name', type: 'text', value: u && u.name },
      { name: 'email', label: 'Email', type: 'text', value: u && u.email },
      { name: 'groups', label: 'Groups', type: 'csv', value: u && u.groups, placeholder: 'dochub-user, gitea-maintainers', wide: true }
    ], isNew ? 'Create user' : 'Save', async (v) => {
      await api('directory/users', POSTJSON(v));
      toast(isNew ? 'User created' : 'User saved');
      await reload();
    });
  }

  /* ===== boot ===== */

  initTheme();
  window.addEventListener('hashchange', render);
  refresh();
})();
