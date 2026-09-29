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
    x: 'M3.72 3.72a.75.75 0 0 1 1.06 0L8 6.94l3.22-3.22a.749.749 0 0 1 1.275.326.749.749 0 0 1-.215.734L9.06 8l3.22 3.22a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215L8 9.06l-3.22 3.22a.751.751 0 0 1-1.042-.018.751.751 0 0 1-.018-1.042L6.94 8 3.72 4.78a.75.75 0 0 1 0-1.06Z'
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

  /* ===== theme ===== */

  const THEME_KEY = 'mockoidc_theme';

  function pinnedTheme() { return localStorage.getItem(THEME_KEY); }
  function isDark() {
    const pinned = pinnedTheme();
    if (pinned) return pinned === 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  function drawThemeIcon() {
    const btn = $('#theme-toggle');
    btn.replaceChildren(octo(isDark() ? 'sun' : 'moon'));
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
    if (!res.ok) throw new Error('API ' + path + ': HTTP ' + res.status);
    return res.json();
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

  /* ===== state ===== */

  let overview = null;
  let entra = null;

  const ROUTES = ['overview', 'entra'];

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
    if (route === 'entra' && overview && overview.entra && entra) {
      drawEntra(view);
    } else {
      drawOverview(view);
    }
  }

  async function refresh() {
    try {
      overview = await api('overview');
      $('#health').className = 'health dot-on';
    } catch (err) {
      $('#health').className = 'health dot-off';
      $('#view').replaceChildren(el('div', 'error', 'Admin API unreachable: ' + err.message));
      return;
    }
    $('#nav a[data-route="entra"]').classList.toggle('hidden', !overview.entra);
    if (overview.entra) {
      try {
        entra = await api('entra');
      } catch (err) {
        entra = null;
        toast('Failed to load Entra state: ' + err.message, true);
      }
    } else {
      entra = null;
    }
    render();
  }

  /* ===== overview view ===== */

  function drawOverview(view) {
    add(view, el('h1', null, 'Overview'));
    add(view, el('p', 'facts', 'Any /{issuerId} path prefix is a valid issuer; the URLs below use this request\'s origin.'));

    if (!overview) return;
    const cards = add(view, el('div', 'cards'));
    card(cards, 'Interactive login').appendChild(boolChip(overview.interactiveLogin, 'on', 'off'));
    card(cards, 'Rotate refresh token').appendChild(boolChip(overview.rotateRefreshToken, 'on', 'off'));
    card(cards, 'Entra mode').appendChild(boolChip(overview.entra, 'enabled', 'off'));
    card(cards, 'Token callbacks', String((overview.tokenCallbacks || []).length));

    if ((overview.loginPagePath || overview.staticAssetsPath)) {
      const bits = [];
      if (overview.loginPagePath) bits.push('custom login page: ' + overview.loginPagePath);
      if (overview.staticAssetsPath) bits.push('static assets: ' + overview.staticAssetsPath);
      add(view, el('p', 'facts', bits.join(' · ')));
    }

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
    const thead = add(table, el('thead'));
    const hr = add(thead, el('tr'));
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

  function card(parent, label, value) {
    const c = add(parent, el('div', 'card'));
    add(c, el('div', 'label', label));
    add(c, el('div', 'value', value != null ? value : ''));
    return c.querySelector('.value');
  }

  /* ===== entra view ===== */

  function drawEntra(view) {
    add(view, el('h1', null, 'Entra mode'));
    add(view, el('p', 'facts', 'basePath /' + entra.basePath + ' · token expiry ' +
      entra.tokenExpiry + 's · default group limit ' + entra.defaultGroupLimit));

    const cards = add(view, el('div', 'cards'));
    card(cards, 'Tenants', String(entra.tenants.length));
    card(cards, 'Users', String(entra.users.length));
    card(cards, 'Consents', String(entra.consents.length));
    card(cards, 'Active kid', entra.keys.activeKid);

    drawTenants(view, entra.tenants);
    drawUsers(view, entra.users);
    drawConsents(view);
    drawKeys(view);
  }

  function drawTenants(view, tenants) {
    add(view, el('h2', null, 'Tenants'));
    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    for (const h of ['tid', 'Name', 'Domains', 'Group claim', 'Group limit', 'Consent required']) {
      add(hr, el('th', null, h));
    }
    const tbody = add(table, el('tbody'));
    for (const t of tenants) {
      const tr = add(tbody, el('tr'));
      const tidTd = add(tr, el('td'));
      add(tidTd, el('span', 'mono', t.tid));
      add(tr, el('td', null, t.name));
      add(tr, el('td', null, (t.domains || []).join(', ') || '—'));
      const fmtTd = add(tr, el('td'));
      fmtTd.appendChild(chip('chip-accent', t.groupClaimFormat));
      add(tr, el('td', 'num', String(t.groupLimit)));
      const crTd = add(tr, el('td'));
      crTd.appendChild(boolChip(t.consentRequired, 'required', 'not required'));
    }
    if (!tenants.length) add(view, el('div', 'empty', 'No tenants configured.'));
  }

  function drawUsers(view, users) {
    add(view, el('h2', null, 'Users'));
    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    for (const h of ['Username', 'Tenant', 'Name', 'Email', 'Groups', 'AMR', 'Admin', 'Error injection']) {
      add(hr, el('th', null, h));
    }
    const tbody = add(table, el('tbody'));
    for (const u of users) {
      const tr = add(tbody, el('tr'));
      const unTd = add(tr, el('td'));
      add(unTd, el('span', 'mono', u.username));
      const tidTd = add(tr, el('td'));
      add(tidTd, el('span', 'mono', u.tid));
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
    }
    if (!users.length) add(view, el('div', 'empty', 'No users configured.'));
  }

  function drawConsents(view) {
    add(view, el('h2', null, 'Consents'));
    const bar = add(view, el('div', 'toolbar'));
    const reset = add(bar, el('button', 'btn btn-sm btn-danger'));
    reset.type = 'button';
    reset.appendChild(octo('trash'));
    reset.appendChild(document.createTextNode('Reset consents'));
    reset.addEventListener('click', async () => {
      if (!window.confirm('Reset consents to the config seed? Consents granted via the admin consent flow are discarded.')) return;
      reset.disabled = true;
      try {
        await api('entra/reset', { method: 'POST' });
        toast('Consents reset to seed');
        await reloadEntra();
      } catch (err) {
        toast(err.message, true);
      } finally {
        reset.disabled = false;
      }
    });
    const wrap = add(view, el('div', 'table-wrap'));
    const table = add(wrap, el('table'));
    const hr = add(add(table, el('thead')), el('tr'));
    add(hr, el('th', null, 'Client ID'));
    add(hr, el('th', null, 'Tenant'));
    const tbody = add(table, el('tbody'));
    for (const c of entra.consents) {
      const tr = add(tbody, el('tr'));
      const cTd = add(tr, el('td'));
      add(cTd, el('span', 'mono', c.clientId));
      const tTd = add(tr, el('td'));
      add(tTd, el('span', 'mono', c.tid));
    }
    if (!entra.consents.length) add(view, el('div', 'empty', 'No consents granted.'));
  }

  function drawKeys(view) {
    add(view, el('h2', null, 'Signing keys'));
    const panel = add(view, el('div', 'panel'));
    const bar = add(panel, el('div', 'toolbar'));
    const rotate = add(bar, el('button', 'btn btn-sm'));
    rotate.type = 'button';
    rotate.appendChild(octo('sync'));
    rotate.appendChild(document.createTextNode('Rotate keys'));
    rotate.addEventListener('click', async () => {
      if (!window.confirm('Rotate the Entra signing keys? The previous key stays published for verification.')) return;
      rotate.disabled = true;
      try {
        const out = await api('entra/rotate-keys', { method: 'POST' });
        toast('Rotated signing keys; new kid ' + out.kid);
        await reloadEntra();
      } catch (err) {
        toast(err.message, true);
      } finally {
        rotate.disabled = false;
      }
    });
    const kids = add(bar, el('span'));
    kids.appendChild(el('span', 'dim', 'published kids: '));
    (entra.keys.publishedKids || []).forEach((kid) => {
      const c = chip(kid === entra.keys.activeKid ? 'chip-on' : '', kid);
      if (kid === entra.keys.activeKid) c.title = 'active signing key';
      kids.appendChild(c);
    });
  }

  async function reloadEntra() {
    try {
      entra = await api('entra');
      overview = await api('overview');
      $('#health').className = 'health dot-on';
    } catch (err) {
      toast(err.message, true);
      return;
    }
    render();
  }

  /* ===== boot ===== */

  initTheme();
  window.addEventListener('hashchange', render);
  refresh();
})();
