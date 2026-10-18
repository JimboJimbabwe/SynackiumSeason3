// Hover Trace: shows what rendered an element, what code inserted it, and where its data came from.
// Paste into the browser console BEFORE you trigger the thing you want to trace.
//   1. Paste this script.
//   2. Do your search (or whatever makes the item appear).
//   3. Hover the item, press Alt+Q.
// A small card follows the cursor with a summary (component / sink / source / candidate flow).
// Sinks are labelled (HTML parser = risky, plain text = safe). Sources include network responses,
// embedded page data, storage, URL (search/hash/path), cookies, window.name, referrer and postMessage.
// Not hooked: eval/new Function (replacing them can change how page code runs) and location assignments.
// NEW in this version: Alt+Q also pulls the relevant source code and shows it with the flow highlighted:
//   SOURCE READ (likely) -> REQUEST -> SINK -> CALLER, using the recorded call stacks. Script files are
//   re-fetched (same-origin, or cross-origin with CORS), and source maps are followed when present,
//   so minified bundles show the original code when the map embeds it.
// Hotkeys: Alt+Q full trace panel + code, Alt+J copy last trace as JSON, Alt+H toggle hover card, Esc close panel.
// Stop with: __traceCleanup()
(() => {
  if (window.__traceCleanup) window.__traceCleanup();

  const installedAt = new Date().toISOString();
  const MAX_BODY = 2000000;
  const requests = [];
  const domLog = new WeakMap();
  const undo = [];
  let busy = false;
  let current = null;
  let lastTrace = null;

  const cssEsc = s => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/[^\w-]/g, '\\$&');
  const norm = s => String(s).replace(/\s+/g, ' ').trim().toLowerCase();
  const clip = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);

  // Call stack captured at the moment of a hooked call. n = frames between this helper and page code.
  const stack = n => {
    let lines = (new Error().stack || '').split('\n');
    if (/^Error/.test(lines[0])) lines = lines.slice(1);
    return lines.slice(1 + n).map(l => l.trim()).filter(Boolean).slice(0, 12);
  };

  function selectorPath(el) {
    const parts = [];
    while (el && el.nodeType === 1 && el !== document.documentElement) {
      let part = el.tagName.toLowerCase();
      if (el.id) { parts.unshift(`${part}#${cssEsc(el.id)}`); break; }
      const parent = el.parentNode;
      if (parent && parent.children) {
        const sibs = Array.from(parent.children).filter(c => c.tagName === el.tagName);
        if (sibs.length > 1) part += `:nth-of-type(${sibs.indexOf(el) + 1})`;
      }
      parts.unshift(part);
      el = parent;
    }
    return parts.join(' > ');
  }

  // ---------- Hook 1: who inserted this into the DOM ----------
  // Sink classification: what happens to a string written through this API?
  // risky = the browser parses it as HTML/JS/URL, so attacker-influenced text could become markup or code.
  function classify(via, node) {
    const v = String(via).replace(/ = …$/, '');
    const isScript = !!(node && node.tagName === 'SCRIPT');
    if (v === 'innerHTML' || v === 'outerHTML' || v === 'insertAdjacentHTML') return { label: 'HTML parser', risky: true };
    if (v === 'srcdoc') return { label: 'iframe HTML parser', risky: true };
    if (isScript && (v === 'text' || v === 'textContent' || v === 'innerText')) return { label: 'script code', risky: true };
    if (isScript && v === 'src') return { label: 'script URL', risky: true };
    if (isScript) return { label: 'inserts <script> element', risky: true };
    if (/\(string\)$/.test(v) || ['textContent', 'innerText', 'nodeValue', 'data', 'insertAdjacentText'].includes(v)) return { label: 'plain text', risky: false };
    return { label: 'DOM node insert', risky: false };
  }

  const mark = (node, via) => {
    if (!node || busy) return;
    try {
      const prev = domLog.get(node);
      domLog.set(node, {
        via, sink: classify(via, node), time: new Date().toISOString(), stack: stack(2),
        history: prev ? [prev, ...(prev.history || [])].slice(0, 3) : []
      });
    } catch (e) {}
  };

  function patchMethod(proto, name) {
    const orig = proto[name];
    if (typeof orig !== 'function') return;
    proto[name] = function (...args) {
      for (const a of args) {
        if (a && a.nodeType === 11) { for (const c of Array.from(a.childNodes)) mark(c, name); }
        else if (a && a.nodeType) mark(a, name);
        else if (typeof a === 'string' && name !== 'insertAdjacentElement') {
          mark(this, /^insertAdjacent(HTML|Text)$/.test(name) ? name : name + '(string)');
        }
      }
      return orig.apply(this, args);
    };
    undo.push(() => { proto[name] = orig; });
  }

  function patchSetter(proto, prop, pick) {
    const d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      ...d,
      set(v) { mark(pick ? pick(this) : this, prop + ' = …'); return d.set.call(this, v); }
    });
    undo.push(() => Object.defineProperty(proto, prop, d));
  }

  try {
    [[Node.prototype, ['appendChild', 'insertBefore', 'replaceChild']],
     [Element.prototype, ['append', 'prepend', 'before', 'after', 'replaceWith', 'replaceChildren',
                          'insertAdjacentHTML', 'insertAdjacentText', 'insertAdjacentElement']]
    ].forEach(([proto, names]) => names.forEach(n => { try { patchMethod(proto, n); } catch (e) {} }));

    [[Element.prototype, 'innerHTML'],
     [Element.prototype, 'outerHTML', n => n.parentNode],
     [Node.prototype, 'textContent'],
     [HTMLElement.prototype, 'innerText'],
     [Node.prototype, 'nodeValue'],
     [CharacterData.prototype, 'data'],
     [HTMLScriptElement.prototype, 'src'],
     [HTMLScriptElement.prototype, 'text'],
     [HTMLIFrameElement.prototype, 'srcdoc']
    ].forEach(([p, n, pick]) => { try { patchSetter(p, n, pick); } catch (e) {} });
  } catch (e) { console.warn('DOM hooks partially failed', e); }

  // ---------- Hook 1b: sinks that aren't plain DOM node writes ----------
  const attrLog = new WeakMap();   // element -> risky attributes set via setAttribute
  const codeSinks = [];            // document.write / string timers
  const messages = [];             // postMessage data seen (a source)

  const attrKind = (name, value) => {
    if (/^on/i.test(name)) return { kind: 'event-handler JS', risky: true };
    if (name.toLowerCase() === 'srcdoc') return { kind: 'iframe HTML parser', risky: true };
    if (/^(href|src|action|formaction|data|xlink:href)$/i.test(name)) {
      return { kind: 'URL', risky: /^\s*(javascript|data|vbscript):/i.test(String(value)) };
    }
    return null;
  };
  const logAttr = (el, name, value, k) => {
    try {
      const list = attrLog.get(el) || [];
      list.push({ name, value: clip(String(value), 200), kind: k.kind, risky: k.risky, time: new Date().toISOString(), stack: stack(2) });
      attrLog.set(el, list);
    } catch (e) {}
  };
  const logCode = (sink, arg) => {
    try {
      codeSinks.push({ sink, arg: clip(String(arg), 2000), time: new Date().toISOString(), stack: stack(2) });
      if (codeSinks.length > 300) codeSinks.shift();
    } catch (e) {}
  };

  try {
    const oSet = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      if (!busy) { const k = attrKind(String(name), value); if (k) logAttr(this, String(name), value, k); }
      return oSet.apply(this, arguments);
    };
    undo.push(() => { Element.prototype.setAttribute = oSet; });
  } catch (e) {}

  ['write', 'writeln'].forEach(name => {
    try {
      const o = Document.prototype[name];
      Document.prototype[name] = function (...args) {
        if (!busy) logCode('document.' + name + ' (HTML parser)', args.join(''));
        return o.apply(this, args);
      };
      undo.push(() => { Document.prototype[name] = o; });
    } catch (e) {}
  });

  ['setTimeout', 'setInterval'].forEach(name => {
    try {
      const o = window[name];
      window[name] = function (fn) {
        if (typeof fn === 'string' && !busy) logCode(name + '(string) (code)', fn);
        return o.apply(this, arguments);
      };
      undo.push(() => { window[name] = o; });
    } catch (e) {}
  });

  const onMessage = e => {
    try {
      const s = typeof e.data === 'string' ? e.data : JSON.stringify(e.data);
      if (s) { messages.push({ origin: e.origin, data: s.slice(0, 5000) }); if (messages.length > 200) messages.shift(); }
    } catch (err) {}
  };
  window.addEventListener('message', onMessage, true);
  undo.push(() => window.removeEventListener('message', onMessage, true));

  // ---------- Hook 2: network responses (so we can match shown text to data) ----------
  const origFetch = window.fetch;
  if (typeof origFetch === 'function') {
    window.fetch = function (input, init) {
      const entry = {
        kind: 'fetch',
        url: String((input && input.url) || input),
        method: (init && init.method) || (input && input.method) || 'GET',
        time: new Date().toISOString(), stack: stack(1), status: null, body: null
      };
      requests.push(entry);
      return origFetch.apply(this, arguments).then(res => {
        entry.status = res.status;
        try { res.clone().text().then(t => { if (t.length <= MAX_BODY) entry.body = t; }).catch(() => {}); } catch (e) {}
        return res;
      });
    };
    undo.push(() => { window.fetch = origFetch; });
  }

  if (window.XMLHttpRequest) {
    const XP = XMLHttpRequest.prototype;
    const oOpen = XP.open, oSend = XP.send;
    XP.open = function (method, url) {
      this.__traceReq = { kind: 'xhr', method, url: String(url), status: null, body: null };
      return oOpen.apply(this, arguments);
    };
    XP.send = function () {
      const e = this.__traceReq;
      if (e) {
        e.time = new Date().toISOString();
        e.stack = stack(1);
        requests.push(e);
        this.addEventListener('loadend', () => {
          e.status = this.status;
          try {
            let t = null;
            if (this.responseType === '' || this.responseType === 'text') t = this.responseText;
            else if (this.responseType === 'json') t = JSON.stringify(this.response);
            if (t && t.length <= MAX_BODY) e.body = t;
          } catch (err) {}
        });
      }
      return oSend.apply(this, arguments);
    };
    undo.push(() => { XP.open = oOpen; XP.send = oSend; });
  }

  // ---------- Safe serialization (no cycles, no fibers, bounded size) ----------
  const SKIP = new Set(['_owner', '_store', 'return', 'child', 'sibling', 'alternate', 'stateNode']);
  function safe(v, depth = 0, seen = new WeakSet()) {
    if (v == null || typeof v === 'number' || typeof v === 'boolean') return v;
    if (typeof v === 'string') return clip(v, 200);
    if (typeof v === 'function') return `ƒ ${v.name || 'anonymous'}()`;
    if (typeof v === 'symbol' || typeof v === 'bigint') return String(v);
    if (v instanceof Node) return `<${(v.nodeName || '').toLowerCase()}>`;
    if (v instanceof Date) { try { return v.toISOString(); } catch (e) { return 'Invalid Date'; } }
    if (v instanceof Map) return `Map(${v.size})`;
    if (v instanceof Set) return `Set(${v.size})`;
    if (typeof v === 'object') {
      if (seen.has(v)) return '[circular]';
      if (depth >= 3) return Array.isArray(v) ? `[Array(${v.length})]` : '{…}';
      seen.add(v);
      if (Array.isArray(v)) return v.slice(0, 30).map(x => safe(x, depth + 1, seen));
      const out = {};
      Object.keys(v).slice(0, 30).forEach(k => {
        if (SKIP.has(k)) return;
        try { out[k] = safe(v[k], depth + 1, seen); } catch (e) { out[k] = '[unreadable]'; }
      });
      return out;
    }
    return String(v);
  }

  // ---------- Framework detection ----------
  function compName(f) {
    const t = f.type;
    if (!t || typeof t === 'string') return null;
    if (typeof t === 'function') return t.displayName || t.name || 'Anonymous';
    return t.displayName || (t.render && (t.render.displayName || t.render.name)) ||
           (t.type && (t.type.displayName || t.type.name)) || null;
  }

  function reactInfo(el) {
    const key = Object.keys(el).find(k => k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$'));
    if (!key) return null;
    const fiber = el[key];
    const chain = [];
    let nearest = null, source = null;
    for (let f = fiber, i = 0; f && i < 80; f = f.return, i++) {
      if (!source && f._debugSource) source = f._debugSource;
      const name = compName(f);
      if (name) { if (!nearest) nearest = f; if (chain.length < 25) chain.push(name); }
    }
    const owners = [];
    for (let o = fiber._debugOwner, i = 0; o && i < 10; o = o._debugOwner, i++) {
      const nm = compName(o); if (nm) owners.push(nm);
    }
    let state;
    if (nearest) {
      const t = nearest.type;
      const isClass = typeof t === 'function' && t.prototype && t.prototype.isReactComponent;
      if (isClass) state = safe(nearest.memoizedState);
      else {
        const hooks = [];
        let h = nearest.memoizedState;
        while (h && typeof h === 'object' && 'next' in h && hooks.length < 20) { hooks.push(safe(h.memoizedState)); h = h.next; }
        state = hooks;
      }
    }
    return {
      framework: 'React', component: chain[0] || null, chain,
      owners: owners.length ? owners : undefined,
      source: source ? `${source.fileName}:${source.lineNumber}` : undefined,
      hostProps: safe(fiber.memoizedProps),
      componentProps: nearest ? safe(nearest.memoizedProps) : undefined,
      state
    };
  }

  function vueInfo(el) {
    const inst = el.__vueParentComponent;
    if (inst) {
      const chain = [];
      for (let c = inst, i = 0; c && i < 25; c = c.parent, i++) {
        chain.push((c.type && (c.type.name || c.type.__name || String(c.type.__file || '').split('/').pop())) || 'Anonymous');
      }
      return { framework: 'Vue 3', component: chain[0], chain, file: inst.type && inst.type.__file, props: safe(inst.props), state: safe(inst.setupState) };
    }
    const v = el.__vue__;
    if (v) {
      const chain = [];
      for (let c = v, i = 0; c && i < 25; c = c.$parent, i++) chain.push(c.$options.name || c.$options._componentTag || 'Anonymous');
      return { framework: 'Vue 2', component: chain[0], chain, props: safe(v.$props), state: safe(v._data) };
    }
    return null;
  }

  function svelteInfo(el) {
    const loc = el.__svelte_meta && el.__svelte_meta.loc;
    return loc ? { framework: 'Svelte (dev mode)', source: `${loc.file}:${loc.line}:${loc.column}` } : null;
  }

  function angularInfo(el) {
    try {
      const ng = window.ng;
      if (!ng || !ng.getOwningComponent) return null;
      const c = ng.getOwningComponent(el) || (ng.getComponent && ng.getComponent(el));
      if (!c) return null;
      return { framework: 'Angular (dev mode)', component: c.constructor && c.constructor.name, state: safe(c) };
    } catch (e) { return null; }
  }

  function frameworkInfo(el) {
    for (let n = el, hops = 0; n && n.nodeType === 1 && hops < 8; n = n.parentElement, hops++) {
      let info = null;
      try { info = reactInfo(n) || vueInfo(n) || svelteInfo(n) || angularInfo(n); } catch (e) {}
      if (info) { if (n !== el) info.foundOn = selectorPath(n); return info; }
    }
    return null;
  }

  // ---------- Who inserted it ----------
  function domOrigin(el) {
    const order = Array.from(el.childNodes).filter(n => n.nodeType === 3).map(n => [n, 'text inside this element']);
    order.push([el, 'this element']);
    for (let p = el.parentNode; p && p.nodeType === 1; p = p.parentNode) order.push([p, () => 'ancestor ' + selectorPath(p)]);
    for (const [n, label] of order) {
      const rec = domLog.get(n);
      if (rec) {
        // Prefer the step that wrote the content (innerHTML, textContent...) over a later plain node move.
        const content = [rec, ...rec.history].find(x => x.sink.label !== 'DOM node insert') || rec;
        return {
          target: typeof label === 'function' ? label() : label,
          via: content.via, sink: content.sink, at: content.time, stack: content.stack,
          placedBy: content !== rec ? { via: rec.via, at: rec.time, caller: rec.stack[0] || null } : undefined
        };
      }
    }
    return null;
  }

  // ---------- Where the data came from ----------
  function findInJson(obj, needle, path, out, seen, depth) {
    if (out.length >= 5 || obj == null || depth > 14) return;
    const t = typeof obj;
    if (t === 'string' || t === 'number') { if (norm(obj).includes(needle)) out.push(path || '(root)'); return; }
    if (t !== 'object' || seen.has(obj)) return;
    seen.add(obj);
    for (const k of Object.keys(obj)) {
      if (out.length >= 5) return;
      let v; try { v = obj[k]; } catch (e) { continue; }
      findInJson(v, needle, Array.isArray(obj) ? `${path}[${k}]` : (path ? `${path}.${k}` : k), out, seen, depth + 1);
    }
  }
  const jsonHits = (obj, needle) => { const out = []; findInJson(obj, needle, '', out, new WeakSet(), 0); return out; };

  function searchSources(needle) {
    const hits = [];
    for (const r of requests) {
      if (!r.body || !r.body.toLowerCase().includes(needle)) continue;
      let paths = [];
      try { paths = jsonHits(JSON.parse(r.body), needle); } catch (e) {}
      hits.push({
        source: `${r.kind.toUpperCase()} ${r.method} ${r.url}`, status: r.status,
        where: paths.length ? paths : ['(in response text)'],
        requestedBy: (r.stack || []).slice(0, 4)
      });
    }
    ['__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', '__APOLLO_STATE__', '__PRELOADED_STATE__', '__REDUX_STATE__', '__remixContext'].forEach(name => {
      try {
        if (window[name]) { const p = jsonHits(window[name], needle); if (p.length) hits.push({ source: 'window.' + name + ' (server-embedded data)', where: p }); }
      } catch (e) {}
    });
    try {
      document.querySelectorAll('script[type="application/json"], script[type="application/ld+json"]').forEach(s => {
        try { const p = jsonHits(JSON.parse(s.textContent), needle); if (p.length) hits.push({ source: 'inline <script type="' + s.type + '"' + (s.id ? ' id="' + s.id + '"' : '') + '>', where: p }); } catch (e) {}
      });
    } catch (e) {}
    try {
      [['localStorage', localStorage], ['sessionStorage', sessionStorage]].forEach(([nm, st]) => {
        for (let i = 0; i < st.length; i++) {
          const k = st.key(i);
          if (String(st.getItem(k)).toLowerCase().includes(needle)) hits.push({ source: nm, where: [k] });
        }
      });
    } catch (e) {}
    return hits;
  }

  const ownText = el => Array.from(el.childNodes).filter(n => n.nodeType === 3).map(n => n.nodeValue).join(' ').replace(/\s+/g, ' ').trim();

  function candidates(el) {
    const out = [];
    const t = ownText(el) || String(el.innerText || '').trim();
    if (t && t.length <= 300) out.push({ label: 'text', value: t });
    ['value', 'alt', 'title', 'placeholder'].forEach(p => { if (typeof el[p] === 'string' && el[p]) out.push({ label: p, value: el[p] }); });
    ['href', 'src'].forEach(a => { const v = el.getAttribute && el.getAttribute(a); if (v) out.push({ label: a, value: v }); });
    return out.map(c => ({ label: c.label, value: norm(c.value).slice(0, 100) })).filter(c => c.value.length >= 3);
  }

  function listeners(el) {
    if (typeof getEventListeners !== 'function') return null; // console-only API
    try {
      return Object.entries(getEventListeners(el)).map(([type, arr]) => ({
        type,
        handlers: arr.map(l => ({ capture: l.useCapture, name: (l.listener && l.listener.name) || 'anonymous', src: clip(String(l.listener), 160) }))
      }));
    } catch (e) { return null; }
  }

  // URL / cookie / window.name / referrer / postMessage sources. These can match in both directions:
  // the shown text may contain the source value (reflection) or the source may contain the shown text.
  const safeDecode = s => { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (e) { return String(s); } };

  function relate(val, needle) {
    const v = norm(val);
    if (v.length < 3) return null;
    if (v.includes(needle)) return 'shown value appears inside the source';
    if (v.length <= 200 && needle.includes(v)) return 'source value appears inside the shown value';
    return null;
  }

  function liveSources(needle) {
    const hits = [];
    const add = (source, where, val, kind, ctrl) => {
      const relation = relate(val, needle);
      if (relation) hits.push({ source, where: [where], sourceKind: kind, controllable: ctrl, relation, value: clip(norm(val), 100) });
    };
    try {
      new URLSearchParams(location.search).forEach((v, k) => add('location.search', '?' + k, v, 'URL', true));
      const hash = location.hash.replace(/^#/, '');
      if (hash) {
        if (hash.includes('=')) new URLSearchParams(hash).forEach((v, k) => add('location.hash', '#' + k, v, 'URL', true));
        add('location.hash', '#…', safeDecode(hash), 'URL', true);
      }
      safeDecode(location.pathname).split('/').filter(Boolean).forEach((seg, i) => add('location.pathname', 'segment ' + i, seg, 'URL', true));
    } catch (e) {}
    try {
      document.cookie.split(';').forEach(c => {
        const i = c.indexOf('=');
        if (i > 0) add('document.cookie', c.slice(0, i).trim(), safeDecode(c.slice(i + 1)), 'cookie', false);
      });
    } catch (e) {}
    try { if (window.name) add('window.name', 'window.name', window.name, 'window.name', true); } catch (e) {}
    try { if (document.referrer) add('document.referrer', 'referrer', safeDecode(document.referrer), 'referrer', true); } catch (e) {}
    messages.forEach(m => add('postMessage from ' + m.origin, 'event.data', m.data, 'postMessage', true));
    return hits;
  }

  function kindOf(source) {
    if (/^(FETCH|XHR) /.test(source)) return 'network response';
    if (/^window\.|^inline <script/.test(source)) return 'embedded page data';
    if (/^(localStorage|sessionStorage)$/.test(source)) return 'storage';
    return 'other';
  }

  function trace(el) {
    const needles = candidates(el);
    const seen = new Set();
    const dataSources = [];
    const addSource = (n, m) => {
      const k = JSON.stringify([m.source, m.where]);
      if (seen.has(k)) return;
      seen.add(k);
      dataSources.push({ matched: `${n.label}: "${n.value}"`, sourceKind: kindOf(m.source), controllable: false, ...m });
    };
    needles.forEach(n => {
      searchSources(n.value).forEach(m => addSource(n, m));
      liveSources(n.value).forEach(m => addSource(n, m));
    });

    const insertedBy = domOrigin(el);
    const attrSinks = (attrLog.get(el) || []).slice(-10);
    const codeHits = codeSinks.filter(c => needles.some(n => c.arg.toLowerCase().includes(n.value)));

    // Candidate flows: a URL/postMessage/etc. source whose value shows up at a sink.
    // Based on value matching, not real taint tracking, so treat it as a lead.
    const flows = [];
    dataSources.filter(d => d.controllable).forEach(d => {
      const src = `${d.source} (${d.where[0]})`;
      if (insertedBy) flows.push({ source: src, sink: `${insertedBy.sink.label} via ${insertedBy.via}`, risky: insertedBy.sink.risky, relation: d.relation });
      attrSinks.filter(a => d.value && a.value.toLowerCase().includes(d.value)).forEach(a =>
        flows.push({ source: src, sink: `setAttribute(${a.name}) → ${a.kind}`, risky: a.risky, relation: d.relation }));
      codeHits.filter(c => d.value && c.arg.toLowerCase().includes(d.value)).forEach(c =>
        flows.push({ source: src, sink: c.sink, risky: true, relation: d.relation }));
    });

    return {
      element: selectorPath(el),
      textShown: ownText(el) || null,
      framework: frameworkInfo(el),
      insertedBy,
      dataSources,
      flows,
      attrSinks,
      codeSinks: codeHits.slice(-5),
      listeners: listeners(el),
      hooksInstalledAt: installedAt,
      requestsLogged: requests.length
    };
  }

  // ---------- Source code view ----------
  const srcCache = new Map();   // script url -> Promise<{ doc, map, mapDocs } | null>
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const LIB = /node_modules|react-dom|react\.|vendor|jquery|lodash|polyfill|chunk-vendors|framework/i;
  // Use the ORIGINAL fetch so our own source downloads don't show up in the request log.
  const rawFetch = u => (origFetch || window.fetch).call(window, u, { credentials: 'same-origin' });

  function vlq(str) {
    const out = [];
    let shift = 0, val = 0;
    for (let i = 0; i < str.length; i++) {
      const d = B64.indexOf(str[i]);
      if (d < 0) return out;
      val += (d & 31) << shift;
      if (d & 32) shift += 5;
      else { const neg = val & 1; val >>= 1; out.push(neg ? -val : val); val = 0; shift = 0; }
    }
    return out;
  }

  // Generated (line, col), both 1-based, -> original source position via a standard v3 source map.
  function mapPos(map, line, col) {
    const lines = map.__lines || (map.__lines = map.mappings.split(';'));
    let src = 0, oLine = 0, oCol = 0;
    for (let l = 0; l < lines.length && l <= line - 1; l++) {
      let gCol = 0, best = null;
      if (lines[l]) {
        for (const seg of lines[l].split(',')) {
          const v = vlq(seg);
          if (!v.length) continue;
          gCol += v[0];
          if (v.length >= 4) {
            src += v[1]; oLine += v[2]; oCol += v[3];
            if (l === line - 1 && gCol <= col - 1) best = { src, oLine, oCol };
          }
        }
      }
      if (l === line - 1) {
        if (!best) return null;
        const root = map.sourceRoot ? String(map.sourceRoot).replace(/\/?$/, '/') : '';
        return {
          source: root + map.sources[best.src], line: best.oLine + 1, col: best.oCol + 1,
          content: map.sourcesContent && map.sourcesContent[best.src] != null ? map.sourcesContent[best.src] : null
        };
      }
    }
    return null;
  }

  async function loadMap(ref, base) {
    try {
      let json;
      if (/^data:/i.test(ref)) {
        const comma = ref.indexOf(',');
        const meta = ref.slice(0, comma), data = ref.slice(comma + 1);
        json = /;base64/i.test(meta)
          ? new TextDecoder().decode(Uint8Array.from(atob(data), c => c.charCodeAt(0)))
          : decodeURIComponent(data);
      } else {
        const res = await rawFetch(new URL(ref, base).href);
        if (!res.ok) return null;
        json = await res.text();
      }
      const map = JSON.parse(json.replace(/^\)\]\}'[^\n]*\n/, ''));
      if (!map || typeof map.mappings !== 'string' || !Array.isArray(map.sources) || map.sections) return null;
      return map;
    } catch (e) { return null; }
  }

  function makeDoc(name, text, url) {
    const starts = [0];
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
    return { name, text, starts, url };
  }
  const lineText = (doc, n) => {
    const s = doc.starts[n - 1];
    if (s === undefined) return null;
    const e = n < doc.starts.length ? doc.starts[n] - 1 : doc.text.length;
    return doc.text.slice(s, e).replace(/\r$/, '');
  };
  const idxOf = (doc, line, col) => (doc.starts[line - 1] || 0) + col - 1;
  const lineOfIdx = (doc, idx) => {
    let lo = 0, hi = doc.starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (doc.starts[mid] <= idx) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };

  function loadScript(url) {
    if (srcCache.has(url)) return srcCache.get(url);
    const p = (async () => {
      try {
        const res = await rawFetch(url);
        if (!res.ok) return null;
        const text = await res.text();
        if (text.length > 8e6) return null;
        const entry = { doc: makeDoc(url.split('/').pop().split('?')[0] || url, text, url), map: null, mapDocs: {} };
        let mm, last = null;
        const re = /[#@]\s*sourceMappingURL=([^\s'"*]+)/g;
        while ((mm = re.exec(text))) last = mm[1];
        if (last) entry.map = await loadMap(last, url);
        return entry;
      } catch (e) { return null; }
    })();
    srcCache.set(url, p);
    return p;
  }

  function parseFrame(line) {
    const m = /(https?:\/\/[^\s()]+|file:\/\/[^\s()]+):(\d+):(\d+)\)?\s*$/.exec(line || '');
    return m ? { url: m[1], line: +m[2], col: +m[3], raw: line } : null;
  }

  async function resolveFrame(fr) {
    const fname = fr.url.split('/').pop().split('?')[0] || fr.url;
    const entry = await loadScript(fr.url);
    if (!entry) return { frame: fr, unavailable: true, doc: null, line: fr.line, col: fr.col, name: fname };
    if (entry.map) {
      const pos = mapPos(entry.map, fr.line, fr.col);
      if (pos && pos.content != null) {
        const doc = entry.mapDocs[pos.source] || (entry.mapDocs[pos.source] = makeDoc(pos.source, pos.content, null));
        return { frame: fr, doc, line: pos.line, col: pos.col, original: true, bundle: `${entry.doc.name}:${fr.line}:${fr.col}`, name: pos.source };
      }
      if (pos) {
        return { frame: fr, doc: entry.doc, line: fr.line, col: fr.col, original: false, name: entry.doc.name,
                 originalLoc: `${pos.source}:${pos.line}:${pos.col} (not embedded in the map)` };
      }
    }
    return { frame: fr, doc: entry.doc, line: fr.line, col: fr.col, original: false, name: entry.doc.name };
  }

  // Heuristic: which code patterns read each kind of source?
  function sourceRegex(source) {
    if (/^location\.search/.test(source)) return /location\.search|URLSearchParams|location\.href|document\.URL/g;
    if (/^location\.hash/.test(source)) return /location\.hash|location\.href|document\.URL/g;
    if (/^location\.pathname/.test(source)) return /location\.pathname|location\.href|document\.URL/g;
    if (/^document\.cookie/.test(source)) return /document\.cookie/g;
    if (/^window\.name/.test(source)) return /window\.name/g;
    if (/^document\.referrer/.test(source)) return /document\.referrer/g;
    if (/^postMessage/.test(source)) return /addEventListener\(\s*['"]message['"]|\.onmessage\b/g;
    if (/^(localStorage|sessionStorage)$/.test(source)) return new RegExp(source, 'g');
    return null;
  }

  async function buildCodeView(t) {
    const items = [];
    const seen = new Set();
    const add = it => {
      const key = (it.doc ? it.doc.name : it.name) + ':' + it.line + ':' + it.col + ':' + it.role;
      if (seen.has(key)) return;
      seen.add(key);
      items.push(it);
    };
    const framesOf = (arr, max) => (arr || []).map(parseFrame).filter(Boolean).slice(0, max);

    // Sink side: where the value was written, plus who called that code
    const sinkSets = [];
    if (t.insertedBy) sinkSets.push({ frames: framesOf(t.insertedBy.stack, 8), label: `${t.insertedBy.via} · ${t.insertedBy.sink.label}`, risky: t.insertedBy.sink.risky });
    (t.attrSinks || []).filter(a => a.risky).slice(-1).forEach(a => sinkSets.push({ frames: framesOf(a.stack, 6), label: `setAttribute(${a.name}) · ${a.kind}`, risky: true }));
    (t.codeSinks || []).slice(-1).forEach(c => sinkSets.push({ frames: framesOf(c.stack, 6), label: c.sink, risky: true }));
    for (const s of sinkSets) {
      const res = await Promise.all(s.frames.map(resolveFrame));
      if (!res.length) continue;
      res.forEach(r => { r.lib = LIB.test(r.frame.url + ' ' + r.name); });
      add({ ...res[0], role: 'SINK', label: s.label, risky: s.risky });
      res.slice(1).sort((a, b) => a.lib - b.lib).slice(0, 3).forEach(r => add({ ...r, role: 'CALLER', label: 'called from', risky: false }));
    }

    // Source side (network): the code that made the request
    for (const d of t.dataSources.filter(d => d.sourceKind === 'network response').slice(0, 2)) {
      const res = await Promise.all(framesOf(d.requestedBy, 3).map(resolveFrame));
      if (res[0]) add({ ...res[0], role: 'REQUEST', label: d.source, risky: false });
    }

    // Source side (URL, cookie, postMessage, storage...): likely read sites near the sink code
    const anchors = items.filter(i => (i.role === 'SINK' || i.role === 'CALLER') && i.doc);
    for (const d of t.dataSources) {
      const re = sourceRegex(d.source);
      if (!re || !anchors.length) continue;
      const cands = [], seenIdx = new Set();
      for (const a of anchors) {
        const base = idxOf(a.doc, a.line, a.col);
        re.lastIndex = 0;
        let m, guard = 0;
        while ((m = re.exec(a.doc.text)) && guard++ < 2000) {
          if (m[0].length === 0) { re.lastIndex++; continue; }
          const k = a.doc.name + ':' + m.index;
          if (seenIdx.has(k)) continue;
          seenIdx.add(k);
          const dist = Math.abs(m.index - base);
          if (dist <= 6000) cands.push({ doc: a.doc, idx: m.index, len: m[0].length, dist });
        }
      }
      const seenLines = new Set();
      cands.sort((x, y) => x.dist - y.dist).filter(c => {
        const k = c.doc.name + ':' + lineOfIdx(c.doc, c.idx);
        if (seenLines.has(k)) return false;
        seenLines.add(k);
        return true;
      }).slice(0, 2).forEach(c => {
        const line = lineOfIdx(c.doc, c.idx);
        add({ doc: c.doc, line, col: c.idx - c.doc.starts[line - 1] + 1, hitLen: c.len, name: c.doc.name,
              role: 'SOURCE READ', label: `${d.source} (likely read, matched by pattern)`, risky: false, original: false });
      });
    }

    const order = { 'SOURCE READ': 0, REQUEST: 1, SINK: 2, CALLER: 3 };
    return items.sort((a, b) => order[a.role] - order[b.role]);
  }

  // ----- snippet + highlighting -----
  const PATS = [
    [/\b(innerHTML|outerHTML|insertAdjacentHTML|document\.writeln?|srcdoc|eval|new Function)\b/g, 'risky'],
    [/\b(textContent|innerText|nodeValue|appendChild|insertAdjacentText|setAttribute|createTextNode)\b/g, 'safe'],
    [/(location\.(?:search|hash|href|pathname)|URLSearchParams|document\.(?:cookie|referrer|URL)|window\.name|localStorage|sessionStorage|\bfetch\s*\(|XMLHttpRequest|addEventListener\(\s*['"]message['"]|\.onmessage\b)/g, 'src']
  ];
  const MARK_STYLE = {
    col: 'background:#f38ba8;color:#1e1e2e;font-weight:bold;border-radius:2px',
    risky: 'color:#f38ba8;font-weight:bold',
    safe: 'color:#89b4fa',
    src: 'color:#f9e2af;font-weight:bold'
  };

  function tokenAt(text, c0) {
    let s = Math.max(0, Math.min(c0, text.length - 1));
    const w = /[\w$]/;
    if (w.test(text[s] || '')) {
      while (s > 0 && w.test(text[s - 1])) s--;
      let e = s;
      while (e < text.length && w.test(text[e])) e++;
      return { s, e };
    }
    const m = /[\w$]+/.exec(text.slice(s, s + 12));
    return m ? { s: s + m.index, e: s + m.index + m[0].length } : { s, e: Math.min(text.length, s + 1) };
  }

  function paintLine(text, colMark) {
    let marks = [];
    PATS.forEach(([re, cls]) => {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        marks.push({ s: m.index, e: m.index + m[0].length, cls });
      }
    });
    if (colMark) {
      marks = marks.filter(p => !(p.e > colMark.s && p.s < colMark.e));
      marks.push({ s: colMark.s, e: colMark.e, cls: 'col' });
    }
    marks.sort((a, b) => a.s - b.s);
    let out = '', cur = 0;
    marks.forEach(mk => {
      if (mk.s < cur) return;
      out += esc(text.slice(cur, mk.s)) + `<span style="${MARK_STYLE[mk.cls]}">${esc(text.slice(mk.s, mk.e))}</span>`;
      cur = mk.e;
    });
    return out + esc(text.slice(cur));
  }

  function snippet(doc, line, col, ctx = 3) {
    const L = lineText(doc, line);
    if (L == null) return null;
    const rows = [];
    if (L.length > 400) {                       // minified: show a character window around the column
      const c0 = col - 1;
      const s = Math.max(0, c0 - 200), e = Math.min(L.length, c0 + 300);
      rows.push({ n: line, text: (s > 0 ? '…' : '') + L.slice(s, e) + (e < L.length ? '…' : ''), hit: true, colAt: c0 - s + (s > 0 ? 1 : 0) });
    } else {
      for (let n = Math.max(1, line - ctx); n <= Math.min(doc.starts.length, line + ctx); n++) {
        rows.push({ n, text: lineText(doc, n), hit: n === line, colAt: n === line ? col - 1 : -1 });
      }
    }
    return { rows };
  }

  const ROLE_COLOR = { 'SOURCE READ': '#f9e2af', REQUEST: '#f9e2af', SINK: '#f38ba8', CALLER: '#6c7086' };

  function codeHtml(items, t) {
    let h = head('Code involved in this flow');
    const f = t.flows.find(x => x.risky) || t.flows[0];
    const d0 = t.dataSources[0];
    const src = f ? f.source : (d0 ? `${d0.source} (${d0.where[0]})` : null);
    const sink = f ? f.sink : (t.insertedBy ? `${t.insertedBy.sink.label} via ${t.insertedBy.via}` : null);
    if (src || sink) h += `${green(src || 'unknown source')}  →  ${green(sink || 'unknown sink')}\n`;
    h += `<span style="color:#6c7086">red = risky sink API · blue = safe sink API · yellow = source API · pink box = exact call position. SOURCE READ lines are guessed by pattern; the rest come from recorded call stacks.</span>\n`;
    if (!items.length) return h + 'No script locations to show. The frames came from the console, eval or an extension, or nothing was recorded.\n';

    items.forEach(it => {
      const color = ROLE_COLOR[it.role] || '#cdd6f4';
      h += `\n<b style="color:${color}">${esc(it.role)}</b> ${esc(it.label)}${it.risky ? ' <span style="color:#f38ba8">⚠</span>' : ''}\n`;
      if (it.unavailable) {
        h += `${green(it.frame.url + ':' + it.frame.line + ':' + it.frame.col)}\n<span style="color:#6c7086">source unavailable (cross-origin without CORS, blocked by CSP, or not downloadable)</span>\n`;
        return;
      }
      h += `${green(it.name + ':' + it.line + ':' + it.col)}`;
      if (it.original) h += ` <span style="color:#6c7086">(via source map, bundle ${esc(it.bundle)})</span>`;
      if (it.originalLoc) h += ` <span style="color:#6c7086">original: ${esc(it.originalLoc)}</span>`;
      h += '\n';
      const sn = snippet(it.doc, it.line, it.col);
      if (!sn) return;
      h += `<div style="white-space:pre;overflow-x:auto;background:#181825;border-radius:6px;padding:6px 8px;margin:4px 0;tab-size:2">`;
      sn.rows.forEach(r => {
        let colMark = null;
        if (r.hit) colMark = it.hitLen ? { s: r.colAt, e: r.colAt + it.hitLen } : tokenAt(r.text, r.colAt);
        h += `<div style="${r.hit ? 'background:rgba(243,139,168,.16);' : ''}"><span style="color:#6c7086;user-select:none">${esc(String(r.n).padStart(5))}  </span>${paintLine(r.text, colMark)}</div>`;
      });
      h += `</div>`;
    });
    return h;
  }

  function plainItem(it) {
    const sn = it.doc ? snippet(it.doc, it.line, it.col) : null;
    return {
      role: it.role, label: it.label,
      location: it.unavailable ? `${it.frame.url}:${it.frame.line}:${it.frame.col}` : `${it.name}:${it.line}:${it.col}`,
      viaSourceMap: it.original ? it.bundle : undefined,
      unavailable: it.unavailable || undefined,
      lines: sn ? sn.rows.map(r => ({ n: r.n, hit: r.hit, text: r.text })) : undefined
    };
  }

  // ---------- UI ----------
  const ui = document.createElement('div');
  ui.style.cssText = 'position:fixed;z-index:2147483646;pointer-events:none;border:2px solid #f38ba8;background:rgba(243,139,168,.12);display:none;';
  const panel = document.createElement('div');
  panel.style.cssText = 'position:fixed;z-index:2147483647;top:12px;right:12px;width:min(720px,96vw);max-height:84vh;overflow:auto;' +
    'background:#1e1e2e;color:#cdd6f4;font:12px/1.45 monospace;padding:12px 14px;border-radius:10px;' +
    'box-shadow:0 8px 28px rgba(0,0,0,.5);display:none;white-space:pre-wrap;word-break:break-word;';
  const card = document.createElement('div');
  card.style.cssText = 'position:fixed;z-index:2147483647;pointer-events:none;max-width:380px;' +
    'background:#1e1e2e;color:#cdd6f4;font:12px/1.45 monospace;padding:8px 10px;border-radius:8px;' +
    'box-shadow:0 4px 16px rgba(0,0,0,.4);display:none;white-space:pre-wrap;word-break:break-word;';
  document.documentElement.appendChild(ui);
  document.documentElement.appendChild(panel);
  document.documentElement.appendChild(card);
  let cardOn = true;
  let cardTimer = null;

  const esc = s => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  const head = t => `\n<b style="color:#f9e2af">${t}</b>\n`;
  const green = s => `<span style="color:#a6e3a1">${esc(s)}</span>`;
  const json = o => clip(JSON.stringify(o, null, 2) || String(o), 1500);

  function render(r) {
    let h = `<b style="color:#f38ba8">TRACE</b> <span style="color:#6c7086">Esc closes · Alt+J copies JSON · full objects logged to console</span>\n`;
    h += `<span style="color:#89b4fa">${esc(r.element)}</span>\n`;
    if (r.textShown) h += `shows: <span style="color:#fab387">"${esc(clip(r.textShown, 120))}"</span>\n`;

    if (r.flows && r.flows.length) {
      h += head('Candidate source → sink flows');
      r.flows.forEach(f => {
        h += `${f.risky ? '<span style="color:#f38ba8">⚠ RISKY</span>' : '<span style="color:#6c7086">safe sink</span>'} ${green(f.source)} → ${green(f.sink)}\n  <span style="color:#6c7086">${esc(f.relation)}</span>\n`;
      });
      h += `<span style="color:#6c7086">Found by matching values, not true taint tracking. Treat as a lead to verify.</span>\n`;
    }

    h += head('1. Component (what rendered it)');
    if (r.framework) {
      const f = r.framework;
      h += `${esc(f.framework)}${f.foundOn ? ' (found on ' + esc(f.foundOn) + ')' : ''}\n`;
      if (f.chain) h += `chain: ${green(f.chain.join(' ‹ '))}\n`;
      else if (f.component) h += `component: ${green(f.component)}\n`;
      if (f.owners) h += `rendered by (dev): ${green(f.owners.join(' ‹ '))}\n`;
      if (f.source || f.file) h += `source: ${green(f.source || f.file)}\n`;
      if (f.componentProps) h += `props:\n${green(json(f.componentProps))}\n`;
      if (f.props) h += `props:\n${green(json(f.props))}\n`;
      if (f.hostProps) h += `element props:\n${green(json(f.hostProps))}\n`;
      if (f.state !== undefined) h += `state:\n${green(json(f.state))}\n`;
    } else h += 'No React/Vue/Angular/Svelte data on this element or its parents.\n';

    h += head('2. Code that put it on the page');
    if (r.insertedBy) {
      const sk = r.insertedBy.sink;
      h += `via ${green(r.insertedBy.via)} on ${esc(r.insertedBy.target)} at ${esc(r.insertedBy.at)}\n`;
      h += `sink: ${green(sk.label)} ${sk.risky ? '<span style="color:#f38ba8">⚠ parses its input as markup/code/URL</span>' : '<span style="color:#6c7086">(safe for text)</span>'}\n`;
      h += green(r.insertedBy.stack.join('\n')) + '\n';
      if (r.insertedBy.placedBy) {
        const p = r.insertedBy.placedBy;
        h += `then placed on the page by ${green(p.via)} at ${esc(p.at)}\n  ${esc((p.caller || '').replace(/^at /, ''))}\n`;
      }
    } else h += 'No insertion recorded since hooks were installed. It was likely in the original server HTML, or rendered before you pasted this.\n';

    h += head('3. Where the shown value came from');
    if (r.dataSources.length) {
      r.dataSources.forEach(s => {
        h += `<span style="color:#fab387">${esc(s.matched)}</span>\n  source: ${green(s.source)}${s.status ? ' [' + s.status + ']' : ''} <span style="color:#6c7086">(${esc(s.sourceKind)}${s.controllable ? ', URL/page-controllable' : ''})</span>\n  at ${green(s.where.join(', '))}\n`;
        if (s.relation) h += `  <span style="color:#6c7086">${esc(s.relation)}</span>\n`;
        if (s.requestedBy && s.requestedBy.length) h += `  requested by:\n  ${esc(s.requestedBy.join('\n  '))}\n`;
      });
    } else h += 'No match in captured requests, embedded page data, storage, URL, cookies, window.name, referrer or postMessage.\n';

    if (r.attrSinks && r.attrSinks.length) {
      h += head('Attribute sinks set on this element');
      r.attrSinks.forEach(a => {
        h += `${a.risky ? '<span style="color:#f38ba8">⚠</span> ' : ''}setAttribute(${esc(a.name)}) → ${green(a.kind)}: ${green(clip(a.value, 80))}\n  ${esc((a.stack[0] || '').replace(/^at /, ''))}\n`;
      });
    }
    if (r.codeSinks && r.codeSinks.length) {
      h += head('Other sinks that received this text');
      r.codeSinks.forEach(c => { h += `<span style="color:#f38ba8">⚠</span> ${green(c.sink)}: ${green(clip(c.arg, 80))}\n  ${esc((c.stack[0] || '').replace(/^at /, ''))}\n`; });
    }

    if (r.listeners && r.listeners.length) {
      h += head('4. Event listeners on this element');
      r.listeners.forEach(l => { h += `${esc(l.type)}: ${green(l.handlers.map(x => x.name).join(', '))}\n`; });
    }
    h += `\n<span style="color:#6c7086">${r.requestsLogged} requests logged since ${esc(r.hooksInstalledAt)}</span>`;
    return h;
  }

  function paint(t, extra, resetScroll) {
    const top = resetScroll ? 0 : panel.scrollTop;
    busy = true;
    try { panel.innerHTML = render(t) + extra; } finally { busy = false; }
    panel.style.display = 'block';
    panel.scrollTop = top;
  }

  function show(el) {
    const t = trace(el);
    lastTrace = t;
    window.__lastTrace = t;
    paint(t, head('Code involved in this flow') + '<span style="color:#6c7086">Loading source code…</span>\n', true);
    console.log('[Hover Trace]', t, el);
    buildCodeView(t).then(items => {
      t.code = items.map(plainItem);
      if (lastTrace === t) paint(t, codeHtml(items, t), false);
      const locs = items.map(i => `${i.role}: ${i.frame ? i.frame.url + ':' + i.frame.line + ':' + i.frame.col : i.name + ':' + i.line + ':' + i.col}`);
      if (locs.length) console.log('[Hover Trace] code locations (click to open in Sources):\n' + locs.join('\n'));
    }).catch(err => {
      if (lastTrace === t) paint(t, head('Code involved in this flow') + 'Source view failed: ' + esc(String(err)) + '\n', false);
    });
  }

  // Short summary shown next to the cursor while hovering
  function renderCard(r) {
    const short = s => clip(String(s).replace(/\(eval at [^)]*\), /, '').replace(/^at /, ''), 90);
    let h = `<span style="color:#89b4fa">${esc(clip(r.element.split(' > ').slice(-2).join(' > '), 70))}</span>\n`;
    const f = r.framework;
    h += `<span style="color:#f9e2af">component</span> ` + (f && (f.component || f.source)
      ? green(`${f.framework}${f.component ? ' · ' + f.component : ''}${f.source ? ' · ' + f.source : ''}`)
      : '<span style="color:#6c7086">none detected</span>') + '\n';
    const ins = r.insertedBy;
    h += `<span style="color:#f9e2af">sink</span> ` + (ins
      ? green(`${ins.sink.label} (${ins.via})`) + (ins.sink.risky ? ' <span style="color:#f38ba8">⚠ parses markup</span>' : ' <span style="color:#6c7086">safe</span>') +
        `\n<span style="color:#f9e2af">  by</span> ${green(ins.stack[0] ? short(ins.stack[0]) : 'unknown caller')}`
      : '<span style="color:#6c7086">not seen (server HTML or before hooks)</span>') + '\n';
    const d = r.dataSources[0];
    h += `<span style="color:#f9e2af">source</span> ` + (d
      ? green(`${d.source} → ${d.where[0]}`) + ` <span style="color:#6c7086">[${esc(d.sourceKind)}${r.dataSources.length > 1 ? ', +' + (r.dataSources.length - 1) + ' more' : ''}]</span>`
      : '<span style="color:#6c7086">no match found</span>') + '\n';
    const risky = (r.flows || []).filter(f => f.risky);
    if (risky.length) h += `<span style="color:#f38ba8">⚠ candidate flow: ${esc(clip(risky[0].source, 40))} → ${esc(clip(risky[0].sink, 40))}</span>\n`;
    else if ((r.flows || []).length) h += `<span style="color:#6c7086">flow: ${esc(clip(r.flows[0].source, 40))} → safe sink</span>\n`;
    h += `<span style="color:#6c7086">Alt+Q full trace · Alt+H hide card</span>`;
    return h;
  }

  function positionCard(x, y) {
    const pad = 16, w = card.offsetWidth, hgt = card.offsetHeight;
    let left = x + pad, top = y + pad;
    if (left + w > innerWidth) left = x - w - pad;
    if (top + hgt > innerHeight) top = y - hgt - pad;
    card.style.left = Math.max(0, left) + 'px';
    card.style.top = Math.max(0, top) + 'px';
  }

  function updateCard(el) {
    if (!cardOn || el !== current) return;
    let r;
    try { r = trace(el); } catch (err) { return; }
    busy = true;
    try { card.innerHTML = renderCard(r); } finally { busy = false; }
    card.style.display = 'block';
  }

  function onMove(e) {
    const el = e.composedPath ? e.composedPath()[0] : e.target;
    if (!el || el.nodeType !== 1 || el === ui || el === card || panel.contains(el)) return;
    const changed = el !== current;
    current = el;
    const r = el.getBoundingClientRect();
    Object.assign(ui.style, { display: 'block', left: r.left + 'px', top: r.top + 'px', width: r.width + 'px', height: r.height + 'px' });
    if (changed && cardOn) {
      clearTimeout(cardTimer);
      cardTimer = setTimeout(() => updateCard(el), 80); // debounce so fast mouse moves stay cheap
    }
    if (cardOn && card.style.display !== 'none') positionCard(e.clientX, e.clientY);
  }

  function onKey(e) {
    if (e.key === 'Escape' && panel.style.display !== 'none') { panel.style.display = 'none'; return; }
    if (!e.altKey) return;
    if (e.code === 'KeyH') {
      e.preventDefault();
      cardOn = !cardOn;
      if (!cardOn) { clearTimeout(cardTimer); card.style.display = 'none'; }
      else if (current) updateCard(current);
    }
    else if (e.code === 'KeyQ' && current) { e.preventDefault(); show(current); }
    else if (e.code === 'KeyJ' && lastTrace) {
      e.preventDefault();
      const text = JSON.stringify(lastTrace, null, 2);
      (navigator.clipboard && navigator.clipboard.writeText ? navigator.clipboard.writeText(text) : Promise.reject())
        .then(() => console.log('Trace JSON copied'))
        .catch(() => console.log(text));
    }
  }

  document.addEventListener('mousemove', onMove, true);
  document.addEventListener('keydown', onKey, true);

  window.__traceRequests = requests;
  window.__traceCleanup = () => {
    document.removeEventListener('mousemove', onMove, true);
    document.removeEventListener('keydown', onKey, true);
    undo.forEach(fn => { try { fn(); } catch (e) {} });
    clearTimeout(cardTimer);
    ui.remove(); panel.remove(); card.remove();
    delete window.__traceCleanup;
    console.log('Hover Trace stopped and hooks removed.');
  };

  console.log('Hover Trace active. Now trigger your search/render, hover the result, press Alt+Q. Stop: __traceCleanup()');
})();
