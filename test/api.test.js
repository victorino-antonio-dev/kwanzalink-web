const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { createApp, migrate } = require('../server');
const { Pool } = require('pg');
let srv, base, pool, jar = {};
const call = async (method, path, body, who = 'a') => {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', origin: base, ...(jar[who] ? { cookie: jar[who] } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const sc = r.headers.get('set-cookie'); if (sc) jar[who] = sc.split(';')[0];
  let j = null; try { j = await r.json(); } catch {}
  return { s: r.status, j, h: r.headers };
};
const reg = (email, user, type = 'Criador', who = 'a') => call('POST', '/api/register', { email, password: '12345678', type, page: { name: 'Nome ' + user, user, blocks: [], soc: {}, theme: 't-ivory' } }, who);
before(async () => {
  pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL || 'postgres://kl:kl@localhost/kl_test' });
  await pool.query('drop schema public cascade; create schema public;');
  await migrate(pool);
  const app = createApp({ pool, adminEmail: 'admin@x.pt', noLimit: true });
  srv = app.listen(0); base = 'http://localhost:' + srv.address().port;
});
after(async () => { srv.close(); await pool.end(); });

test('registo, sessão e username/e-mail duplicados', async () => {
  const r = await reg('ana@x.pt', 'ana_s'); assert.equal(r.s, 201); assert.equal(r.j.email, 'ana@x.pt');
  assert.match(r.h.get('set-cookie'), /HttpOnly/);
  const pg0 = await call('GET', '/api/public/ana_s', null, 'anon'); assert.equal(pg0.s, 200, 'página pública existe logo após o registo');
  assert.equal((await reg('ana@x.pt', 'outro_u', 'Criador', 'z')).s, 409);
  const d = await reg('b@x.pt', 'ana_s', 'Criador', 'z'); assert.equal(d.s, 409); assert.match(d.j.error, /username/);
  assert.equal((await reg('c@x.pt', 'admin', 'Criador', 'z')).s, 400);
  assert.equal((await call('POST', '/api/register', { email: 'x', password: '12345678', page: { name: 'a', user: 'abc' } }, 'z')).s, 400);
  assert.equal((await call('POST', '/api/register', { email: 'd@x.pt', password: '123', page: { name: 'a', user: 'abc' } }, 'z')).s, 400);
});
test('palavra-passe guardada com hash', async () => {
  const r = await pool.query("select pw_hash from users where email='ana@x.pt'"); assert.match(r.rows[0].pw_hash, /^\$2[aby]\$/);
});
test('login, logout e erro genérico', async () => {
  assert.equal((await call('POST', '/api/login', { email: 'ana@x.pt', password: 'errada123' }, 'l')).s, 401);
  assert.equal((await call('POST', '/api/login', { email: 'naoexiste@x.pt', password: '12345678' }, 'l')).s, 401);
  const ok = await call('POST', '/api/login', { email: 'ana@x.pt', password: '12345678' }, 'l'); assert.equal(ok.s, 200);
  assert.equal((await call('GET', '/api/me', null, 'l')).s, 200);
  await call('POST', '/api/logout', {}, 'l');
  assert.equal((await call('GET', '/api/me', null, 'l')).s, 401);
});
test('guardar documento, snapshot público e analytics', async () => {
  const me = await call('GET', '/api/me'); const doc = { ...me.j.doc, products: [{ id: 'p1', title: 'Guia', price: 7500, status: 'ativo' }] };
  assert.equal((await call('PUT', '/api/me', { doc, pub: { page: { name: 'Nome ana_s', user: 'ana_s', blocks: [] } } })).s, 200);
  const again = await call('GET', '/api/me'); assert.equal(again.j.doc.products[0].title, 'Guia');
  const p = await call('GET', '/api/public/ana_s', null, 'anon'); assert.equal(p.s, 200); assert.equal(p.j.page.user, 'ana_s');
  assert.equal((await call('GET', '/api/public/naoexiste', null, 'anon')).s, 404);
  assert.equal((await call('PUT', '/api/me', { doc: { ...doc, page: { ...doc.page, user: 'roubado' } } })).s, 400);
  assert.equal((await call('POST', '/api/public/ana_s/event', { t: 'view' }, 'anon')).s, 204);
  await call('POST', '/api/public/ana_s/event', { t: 'view' }, 'anon'); await call('POST', '/api/public/ana_s/event', { t: 'click', ref: 'Instagram' }, 'anon');
  assert.equal((await call('POST', '/api/public/ana_s/event', { t: 'hack' }, 'anon')).s, 400);
  const an = await call('GET', '/api/me/analytics'); assert.equal(an.j.days.find(d => d.type === 'view').n, 2); assert.equal(an.j.top[0].ref, 'Instagram');
});
test('pedidos de visitantes: idempotência, entrega e confirmação', async () => {
  const body = { kind: 'order', key: 'abcdefgh-1', data: { cust: 'João', contact: '244911222333', item: 'Guia', amount: 7500 } };
  assert.equal((await call('POST', '/api/public/ana_s/inbox', body, 'anon')).s, 201);
  await call('POST', '/api/public/ana_s/inbox', body, 'anon');
  assert.equal((await call('POST', '/api/public/ana_s/inbox', { ...body, data: { cust: '' } }, 'anon')).s, 400);
  assert.equal((await call('POST', '/api/public/nada/inbox', body, 'anon')).s, 404);
  const me = await call('GET', '/api/me'); assert.equal(me.j.inbox.length, 1); assert.equal(me.j.inbox[0].data.cust, 'João');
  await call('PUT', '/api/me', { doc: me.j.doc, ack: [me.j.inbox[0].id] });
  assert.equal((await call('GET', '/api/me')).j.inbox.length, 0);
});
test('CSRF e tipo de conteúdo', async () => {
  const r = await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: '{}' }); assert.equal(r.status, 403);
  const t = await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' }); assert.equal(t.status, 415);
});
test('administração: acesso, suspensão, levantamentos e taxas', async () => {
  assert.equal((await call('GET', '/api/admin/overview')).s, 403);
  assert.equal((await reg('admin@x.pt', 'chefe', 'Criador', 'adm')).s, 201);
  const ov = await call('GET', '/api/admin/overview', null, 'adm'); assert.equal(ov.s, 200); assert.ok(ov.j.users.length >= 2);
  const me = await call('GET', '/api/me'); await call('PUT', '/api/me', { doc: { ...me.j.doc, payouts: [{ id: 'pp1', amount: 10000, status: 'em revisão', date: '2026-10-09' }] } });
  assert.equal((await call('POST', '/api/admin/payout', { email: 'ana@x.pt', id: 'pp1', status: 'processado' }, 'adm')).s, 200);
  assert.equal((await call('POST', '/api/admin/payout', { email: 'ana@x.pt', id: 'pp1', status: 'rejeitado' }, 'adm')).s, 409);
  assert.equal((await call('GET', '/api/me')).j.doc.payouts[0].status, 'processado');
  assert.equal((await call('PUT', '/api/admin/config', { fee: 9, min: 5000 }, 'adm')).s, 400);
  assert.equal((await call('PUT', '/api/admin/config', { fee: 6, min: 7000 }, 'adm')).s, 200);
  assert.equal((await call('GET', '/api/config', null, 'anon')).j.fee, 6);
  assert.equal((await call('POST', '/api/admin/suspend', { email: 'ana@x.pt', suspended: true }, 'adm')).s, 200);
  assert.equal((await call('GET', '/api/me')).s, 401);
  assert.equal((await call('POST', '/api/login', { email: 'ana@x.pt', password: '12345678' }, 'l2')).s, 403);
  assert.equal((await call('GET', '/api/public/ana_s', null, 'anon')).s, 404);
  assert.equal((await call('POST', '/api/admin/suspend', { email: 'admin@x.pt', suspended: true }, 'adm')).s, 400);
  assert.ok((await call('GET', '/api/admin/overview', null, 'adm')).j.audit.length >= 3);
});
test('alterar palavra-passe e eliminar conta', async () => {
  await reg('eva@x.pt', 'eva_k', 'Marca', 'eva');
  assert.equal((await call('POST', '/api/password', { old: 'errada', next: 'novapass123' }, 'eva')).s, 403);
  assert.equal((await call('POST', '/api/password', { old: '12345678', next: 'novapass123' }, 'eva')).s, 200);
  assert.equal((await call('POST', '/api/login', { email: 'eva@x.pt', password: 'novapass123' }, 'eva2')).s, 200);
  assert.equal((await call('DELETE', '/api/me', { password: 'errada' }, 'eva2')).s, 403);
  assert.equal((await call('DELETE', '/api/me', { password: 'novapass123' }, 'eva2')).s, 200);
  assert.equal((await pool.query("select 1 from users where email='eva@x.pt'")).rowCount, 0);
});
test('página inicial, short link /username e healthz', async () => {
  const idx = await fetch(base + '/'); assert.equal(idx.status, 200);
  assert.match(idx.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal((await fetch(base + '/chefe')).status, 200);
  assert.equal((await fetch(base + '/healthz')).status, 200);
  assert.equal((await fetch(base + '/api/naoexiste')).status, 404);
});
