/* Public build transport only. No credentials, listings, or API responses are cached here. */
'use strict';
const expectedBackend = (() => {
  try {
    const url = new URL(new URL(self.location.href).searchParams.get('backend'));
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !(loopback && url.protocol === 'http:')) ||
        url.username || url.password || url.pathname !== '/' || url.search || url.hash) return '';
    return url.origin;
  } catch { return ''; }
})();
const sessions = new Map();
const pending = new Map();
const scopeURL = new URL(self.registration.scope);
const valid = session => !!session && session.backend === expectedBackend &&
  /^[a-f0-9]{64}$/.test(session.token) && Number.isFinite(session.expiresAt) &&
  session.expiresAt > Date.now();
const belongs = client => {
  if (!client || client.type !== 'window') return false;
  try {
    const url = new URL(client.url);
    return url.origin === scopeURL.origin && url.pathname.startsWith(scopeURL.pathname);
  } catch { return false; }
};
const failure = (status, error, code) => new Response(JSON.stringify({ error, code }), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
});
const notify = async (id, value) => {
  const client = await self.clients.get(id);
  if (belongs(client)) client.postMessage(value);
};

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('message', event => {
  if (event.data?.type !== 'FC_BRIDGE_CONFIG') return;
  const source = event.source;
  const port = event.ports[0];
  if (!belongs(source) || !port) return;
  const session = event.data.session;
  if (session === null) {
    sessions.delete(source.id);
    port.postMessage({ ok: true }); port.close(); return;
  }
  if (!valid(session)) { port.postMessage({ ok: false }); port.close(); return; }
  for (const [id, previous] of sessions) if (!valid(previous)) sessions.delete(id);
  sessions.set(source.id, { backend: expectedBackend, token: session.token, expiresAt: session.expiresAt });
  port.postMessage({ ok: true }); port.close();
});

async function sessionFor(id) {
  const client = await self.clients.get(id);
  if (!belongs(client)) return null;
  const current = sessions.get(id);
  if (valid(current)) return current;
  if (pending.has(id)) return pending.get(id);
  // Workers can be suspended at any time. Recover only from the requesting tab.
  const recovery = new Promise(resolve => {
    const channel = new MessageChannel();
    const timeout = setTimeout(() => { channel.port1.close(); resolve(null); }, 3000);
    channel.port1.onmessage = event => {
      clearTimeout(timeout); channel.port1.close();
      const value = event.data?.session;
      if (!valid(value)) { resolve(null); return; }
      const session = { backend: expectedBackend, token: value.token, expiresAt: value.expiresAt };
      sessions.set(id, session); resolve(session);
    };
    client.postMessage({ type: 'FC_BRIDGE_NEEDS_SESSION' }, [channel.port2]);
  }).finally(() => pending.delete(id));
  pending.set(id, recovery);
  return recovery;
}

async function proxy(event, url) {
  const session = await sessionFor(event.clientId);
  if (!session) {
    await notify(event.clientId, { type: 'FC_BRIDGE_EXPIRED' });
    return failure(401, '连接已过期，请重新输入电脑提供的访问码。', 'phone_access_required');
  }
  const request = event.request;
  const headers = new Headers();
  for (const name of ['accept', 'content-type', 'range']) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  headers.set('X-FC-Access', session.token);
  try {
    // A new CORS request also lets <img> use this authenticated transport.
    const response = await fetch(session.backend + url.pathname + url.search, {
      method: request.method, headers,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
      credentials: 'omit', mode: 'cors', cache: 'no-store', redirect: 'error',
      signal: request.signal,
    });
    if (response.status === 401) {
      const body = await response.clone().json().catch(() => null);
      if (body?.code === 'phone_access_required') {
        if (sessions.get(event.clientId)?.token === session.token) sessions.delete(event.clientId);
        await notify(event.clientId, { type: 'FC_BRIDGE_EXPIRED', token: session.token });
      }
    }
    await notify(event.clientId, { type: 'FC_BRIDGE_NETWORK', offline: false });
    // Produce a same-origin response for the controlled page. In particular,
    // an original same-origin fetch cannot consume a tainted CORS Response.
    const responseHeaders = new Headers(response.headers);
    for (const name of ['content-encoding', 'content-length', 'transfer-encoding', 'set-cookie'])
      responseHeaders.delete(name);
    responseHeaders.set('Cache-Control', 'no-store');
    return new Response(response.body, {
      status: response.status, statusText: response.statusText, headers: responseHeaders,
    });
  } catch (error) {
    if (request.signal.aborted || error?.name === 'AbortError') throw error;
    await notify(event.clientId, { type: 'FC_BRIDGE_NETWORK', offline: true });
    return failure(503, '暂时无法连接电脑，请检查网络，并确认电脑和公网通道保持运行。', 'computer_offline');
  }
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  // No arbitrary-host forwarding, navigation interception, caching, or static fallback.
  if (url.origin !== scopeURL.origin || !url.pathname.startsWith('/api/')) return;
  event.respondWith(proxy(event, url));
});
