'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

const RESERVED = new Set(['api','admin','assets','static','public','healthz','login','entrar','registar','u','m','p','mk','c','a','brand','dashboard','www','kwanzalink','suporte','ajuda','termos','privacidade','cookies','precos','criadores','marcas','recursos','sobre','contacto','exemplos']);
const TYPES = ['Criador','Profissional independente','Marca','Agência'];
const USER_RE = /^[a-z0-9_]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const SESSION_DAYS = 30;

function createApp(opts = {}) {
  const pool = opts.pool || new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === '1' ? { rejectUnauthorized: false } : false,
  });
  const adminEmail = (opts.adminEmail ?? process.env.ADMIN_EMAIL ?? '').trim().toLowerCase();
  const isProd = (opts.production ?? process.env.NODE_ENV === 'production');
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ['https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
  }));
  app.use(express.json({ limit: '1mb' }));

  const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  const err = (res, code, msg) => res.status(code).json({ error: msg });
  const sha = s => crypto.createHash('sha256').update(s).digest('hex');
  const lim = (windowMs, max) => rateLimit({ windowMs, limit: max, standardHeaders: true, legacyHeaders: false, message: { error: 'Demasiados pedidos. Tente novamente daqui a pouco.' }, skip: () => opts.noLimit === true });
  const authLimit = lim(15 * 60 * 1000, 30);
  const publicLimit = lim(60 * 1000, 120);
  const writeLimit = lim(60 * 1000, 20);

  // Proteção CSRF: pedidos que alteram dados têm de vir do próprio site.
  app.use('/api', (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const o = req.get('origin');
    if (o) { try { if (new URL(o).host !== req.get('host')) return err(res, 403, 'Origem não permitida.'); } catch { return err(res, 403, 'Origem inválida.'); } }
    if (!req.is('application/json')) return err(res, 415, 'Content-Type deve ser application/json.');
    next();
  });

  const cookieOpts = () => ({ httpOnly: true, sameSite: 'lax', secure: isProd, path: '/', maxAge: SESSION_DAYS * 864e5 });
  const parseCookies = h => Object.fromEntries((h || '').split(';').map(c => c.trim().split('=')).filter(a => a[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
  async function newSession(res, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('insert into sessions(token_hash,user_id,expires_at) values($1,$2,now()+($3||\' days\')::interval)', [sha(token), userId, String(SESSION_DAYS)]);
    res.cookie('kl_sid', token, cookieOpts());
  }
  const auth = wrap(async (req, res, next) => {
    const tok = parseCookies(req.headers.cookie).kl_sid;
    if (!tok) return err(res, 401, 'Sessão iniciada necessária.');
    const r = await pool.query('select u.* from sessions s join users u on u.id=s.user_id where s.token_hash=$1 and s.expires_at>now()', [sha(tok)]);
    const u = r.rows[0];
    if (!u) return err(res, 401, 'Sessão inválida ou expirada.');
    if (u.suspended) return err(res, 403, 'Conta suspensa.');
    req.user = u; req.tokHash = sha(tok);
    next();
  });
  const admin = (req, res, next) => req.user.role === 'admin' ? next() : err(res, 403, 'Acesso restrito à administração.');
  const audit = (actor, action, detail = {}) => pool.query('insert into audit_log(actor,action,detail) values($1,$2,$3)', [actor, action, detail]).catch(() => {});
  const str = (v, n) => String(v ?? '').trim().slice(0, n);
  const out = u => ({ email: u.email, type: u.type, role: u.role, doc: { ...u.doc, type: u.type } });

  app.get('/healthz', wrap(async (req, res) => { await pool.query('select 1'); res.json({ ok: true }); }));
  app.get('/api/config', wrap(async (req, res) => {
    const r = await pool.query("select key,value from settings where key in ('fee','min_payout')");
    const m = Object.fromEntries(r.rows.map(x => [x.key, Number(x.value)]));
    res.set('Cache-Control', 'no-store').json({ server: true, fee: m.fee ?? 5, min: m.min_payout ?? 5000 });
  }));

  // ---- Conta
  app.post('/api/register', authLimit, wrap(async (req, res) => {
    const b = req.body || {};
    const email = str(b.email, 200).toLowerCase(), pw = String(b.password || ''), type = TYPES.includes(b.type) ? b.type : 'Criador';
    const page = b.page && typeof b.page === 'object' ? b.page : null;
    if (!EMAIL_RE.test(email)) return err(res, 400, 'E-mail inválido.');
    if (pw.length < 8 || pw.length > 128) return err(res, 400, 'A palavra-passe deve ter entre 8 e 128 caracteres.');
    if (!page) return err(res, 400, 'Dados da página em falta.');
    const username = str(page.user, 30).toLowerCase();
    if (!USER_RE.test(username) || RESERVED.has(username)) return err(res, 400, 'Username inválido ou reservado.');
    page.user = username; page.name = str(page.name, 100);
    if (!page.name) return err(res, 400, 'Indique o seu nome.');
    const hash = await bcrypt.hash(pw, 10);
    const doc = { page, products: [], services: [], orders: [], bookings: [], creators: [], campaigns: [], deals: [], deliv: [], programs: [], convs: [], team: [], aff: [], earn: [], payouts: [] };
    let u;
    try {
      const r = await pool.query('insert into users(email,username,pw_hash,type,role,doc) values($1,$2,$3,$4,$5,$6) returning *', [email, username, hash, type, email === adminEmail ? 'admin' : 'user', doc]);
      u = r.rows[0];
    } catch (e) {
      if (e.code === '23505') return err(res, 409, e.constraint && e.constraint.includes('username') ? 'Este username já está em uso.' : 'Este e-mail já tem conta.');
      throw e;
    }
    await newSession(res, u.id);
    audit(email, 'register', { username });
    res.status(201).json(out(u));
  }));
  app.post('/api/login', authLimit, wrap(async (req, res) => {
    const email = str(req.body?.email, 200).toLowerCase(), pw = String(req.body?.password || '');
    const r = await pool.query('select * from users where email=$1', [email]);
    const u = r.rows[0];
    const ok = u ? await bcrypt.compare(pw, u.pw_hash) : (await bcrypt.compare(pw, '$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123'), false);
    if (!ok) return err(res, 401, 'E-mail ou palavra-passe incorretos.');
    if (u.suspended) return err(res, 403, 'Esta conta está suspensa. Contacte a equipa.');
    if (email === adminEmail && u.role !== 'admin') { await pool.query("update users set role='admin' where id=$1", [u.id]); u.role = 'admin'; }
    await newSession(res, u.id);
    res.json(out(u));
  }));
  app.post('/api/logout', wrap(async (req, res) => {
    const tok = parseCookies(req.headers.cookie).kl_sid;
    if (tok) await pool.query('delete from sessions where token_hash=$1', [sha(tok)]);
    res.clearCookie('kl_sid', { path: '/' }).json({ ok: true });
  }));
  app.get('/api/me', auth, wrap(async (req, res) => {
    const inbox = (await pool.query('select id,kind,data,created_at from inbox where owner_id=$1 and delivered_at is null order by created_at limit 200', [req.user.id])).rows;
    res.set('Cache-Control', 'no-store').json({ ...out(req.user), inbox });
  }));
  app.put('/api/me', auth, lim(60 * 1000, 120), wrap(async (req, res) => {
    const { doc, pub, ack } = req.body || {};
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return err(res, 400, 'Documento inválido.');
    if (JSON.stringify(doc).length > 900000) return err(res, 413, 'Dados demasiado grandes.');
    if (!doc.page || str(doc.page.user, 30).toLowerCase() !== req.user.username) return err(res, 400, 'O username não pode ser alterado.');
    const { type, ...rest } = doc;
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('update users set doc=$2, updated_at=now() where id=$1', [req.user.id, rest]);
      if (pub && typeof pub === 'object') {
        if (JSON.stringify(pub).length > 400000) { await client.query('rollback'); return err(res, 413, 'Página pública demasiado grande.'); }
        await client.query('insert into public_pages(username,snapshot) values($1,$2) on conflict(username) do update set snapshot=excluded.snapshot, updated_at=now()', [req.user.username, pub]);
      }
      if (Array.isArray(ack) && ack.length) await client.query('update inbox set delivered_at=now() where owner_id=$1 and delivered_at is null and id = any($2::uuid[])', [req.user.id, ack.filter(x => /^[0-9a-f-]{36}$/i.test(x)).slice(0, 500)]);
      await client.query('commit');
    } catch (e) { await client.query('rollback').catch(() => {}); throw e; } finally { client.release(); }
    res.json({ ok: true });
  }));
  app.post('/api/password', auth, authLimit, wrap(async (req, res) => {
    const { old, next } = req.body || {};
    if (!(await bcrypt.compare(String(old || ''), req.user.pw_hash))) return err(res, 403, 'Palavra-passe atual incorreta.');
    if (String(next || '').length < 8 || String(next).length > 128) return err(res, 400, 'A nova palavra-passe deve ter entre 8 e 128 caracteres.');
    await pool.query('update users set pw_hash=$2 where id=$1', [req.user.id, await bcrypt.hash(String(next), 10)]);
    await pool.query('delete from sessions where user_id=$1 and token_hash<>$2', [req.user.id, req.tokHash]);
    audit(req.user.email, 'password_change');
    res.json({ ok: true });
  }));
  app.delete('/api/me', auth, authLimit, wrap(async (req, res) => {
    if (!(await bcrypt.compare(String(req.body?.password || ''), req.user.pw_hash))) return err(res, 403, 'Palavra-passe incorreta.');
    await pool.query('delete from users where id=$1', [req.user.id]);
    audit(req.user.email, 'account_delete');
    res.clearCookie('kl_sid', { path: '/' }).json({ ok: true });
  }));
  app.get('/api/me/analytics', auth, wrap(async (req, res) => {
    const r = await pool.query("select day::text, type, sum(n)::int n from events where username=$1 and day>current_date-30 group by 1,2 order by 1", [req.user.username]);
    const top = await pool.query("select type, ref, sum(n)::int n from events where username=$1 and day>current_date-30 and ref<>'' group by 1,2 order by n desc limit 10", [req.user.username]);
    res.json({ days: r.rows, top: top.rows });
  }));

  // ---- Público
  app.get('/api/public/:username', publicLimit, wrap(async (req, res) => {
    const r = await pool.query('select snapshot from public_pages p join users u on u.username=p.username where p.username=$1 and not u.suspended', [req.params.username.toLowerCase()]);
    if (!r.rows[0]) return err(res, 404, 'Página não encontrada.');
    res.set('Cache-Control', 'public, max-age=30').json(r.rows[0].snapshot);
  }));
  app.post('/api/public/:username/event', publicLimit, wrap(async (req, res) => {
    const t = str(req.body?.t, 12), ref = str(req.body?.ref, 60);
    if (!['view', 'click', 'product'].includes(t)) return err(res, 400, 'Evento inválido.');
    await pool.query('insert into events(day,username,type,ref,n) select current_date,$1,$2,$3,1 where exists(select 1 from users where username=$1) on conflict(day,username,type,ref) do update set n=events.n+1', [req.params.username.toLowerCase(), t, t === 'view' ? '' : ref]);
    res.status(204).end();
  }));
  app.post('/api/public/:username/inbox', writeLimit, wrap(async (req, res) => {
    const b = req.body || {}, kind = str(b.kind, 10), key = str(b.key, 64);
    if (!['order', 'booking'].includes(kind)) return err(res, 400, 'Tipo de pedido inválido.');
    if (key.length < 8) return err(res, 400, 'Chave de pedido inválida.');
    const d = b.data || {}, data = { cust: str(d.cust, 100), contact: str(d.contact, 100), item: str(d.item, 200), amount: Math.max(0, Math.min(1e9, Number(d.amount) || 0)), note: str(d.note, 500), date: str(d.date, 10) };
    if (!data.cust || !data.contact || !data.item) return err(res, 400, 'Indique nome, contacto e item.');
    const u = (await pool.query('select id from users where username=$1 and not suspended', [req.params.username.toLowerCase()])).rows[0];
    if (!u) return err(res, 404, 'Página não encontrada.');
    await pool.query('insert into inbox(owner_id,kind,key,data) values($1,$2,$3,$4) on conflict(owner_id,key) do nothing', [u.id, kind, key, data]);
    res.status(201).json({ ok: true });
  }));

  // ---- Administração
  app.get('/api/admin/overview', auth, admin, wrap(async (req, res) => {
    const r = await pool.query('select email,username,type,role,suspended,created_at,doc from users order by created_at desc limit 1000');
    res.json({ users: r.rows.map(x => ({ email: x.email, username: x.username, type: x.type, role: x.role, suspended: x.suspended, created_at: x.created_at, name: x.doc?.page?.name || '', payouts: x.doc?.payouts || [], bank: x.doc?.bank || null })), audit: (await pool.query('select at,actor,action,detail from audit_log order by id desc limit 100')).rows });
  }));
  app.post('/api/admin/suspend', auth, admin, wrap(async (req, res) => {
    const email = str(req.body?.email, 200).toLowerCase(), s = !!req.body?.suspended;
    if (email === req.user.email) return err(res, 400, 'Não pode suspender a sua própria conta.');
    const r = await pool.query('update users set suspended=$2 where email=$1 returning id', [email, s]);
    if (!r.rows[0]) return err(res, 404, 'Conta não encontrada.');
    if (s) await pool.query('delete from sessions where user_id=$1', [r.rows[0].id]);
    audit(req.user.email, s ? 'suspend' : 'unsuspend', { email });
    res.json({ ok: true });
  }));
  app.delete('/api/admin/user', auth, admin, wrap(async (req, res) => {
    const email = str(req.body?.email, 200).toLowerCase();
    if (email === req.user.email) return err(res, 400, 'Não pode eliminar a sua própria conta.');
    const r = await pool.query('delete from users where email=$1 returning id', [email]);
    if (!r.rows[0]) return err(res, 404, 'Conta não encontrada.');
    audit(req.user.email, 'delete_user', { email });
    res.json({ ok: true });
  }));
  app.post('/api/admin/payout', auth, admin, wrap(async (req, res) => {
    const email = str(req.body?.email, 200).toLowerCase(), id = str(req.body?.id, 40), status = req.body?.status;
    if (!['processado', 'rejeitado'].includes(status)) return err(res, 400, 'Estado inválido.');
    const client = await pool.connect();
    try {
      await client.query('begin');
      const u = (await client.query('select id,doc from users where email=$1 for update', [email])).rows[0];
      const p = u && (u.doc.payouts || []).find(x => x.id === id);
      if (!p) { await client.query('rollback'); return err(res, 404, 'Pedido não encontrado.'); }
      if (p.status !== 'em revisão') { await client.query('rollback'); return err(res, 409, 'Este pedido já foi tratado.'); }
      p.status = status; p.reviewed = new Date().toISOString();
      await client.query('update users set doc=$2 where id=$1', [u.id, u.doc]);
      await client.query('commit');
    } catch (e) { await client.query('rollback').catch(() => {}); throw e; } finally { client.release(); }
    audit(req.user.email, 'payout_' + status, { email, id });
    res.json({ ok: true });
  }));
  app.put('/api/admin/config', auth, admin, wrap(async (req, res) => {
    const fee = Number(req.body?.fee), min = Math.round(Number(req.body?.min));
    if (!(fee >= 3 && fee <= 8)) return err(res, 400, 'A comissão deve estar entre 3% e 8%.');
    if (!(min >= 0 && min <= 1e9)) return err(res, 400, 'Valor mínimo inválido.');
    await pool.query("insert into settings(key,value) values('fee',$1),('min_payout',$2) on conflict(key) do update set value=excluded.value", [String(fee), String(min)]);
    audit(req.user.email, 'config', { fee, min });
    res.json({ ok: true });
  }));

  // ---- Site
  const pub = opts.publicDir || path.join(__dirname, 'public');
  app.use(express.static(pub, { index: 'index.html', maxAge: isProd ? '5m' : 0 }));
  app.get('/:username', (req, res, next) => {
    const u = req.params.username.toLowerCase();
    if (!USER_RE.test(u) || RESERVED.has(u)) return next();
    res.sendFile(path.join(pub, 'index.html'));
  });
  app.use('/api', (req, res) => err(res, 404, 'Rota não encontrada.'));
  app.use((e, req, res, next) => {
    if (e.type === 'entity.too.large') return err(res, 413, 'Pedido demasiado grande.');
    if (e.type === 'entity.parse.failed') return err(res, 400, 'JSON inválido.');
    console.error(JSON.stringify({ level: 'error', msg: e.message, path: req.path }));
    err(res, 500, 'Erro interno.');
  });
  app.pool = pool;
  return app;
}

async function migrate(pool) { await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8')); }

if (require.main === module) {
  const app = createApp();
  migrate(app.pool).then(() => {
    const port = Number(process.env.PORT) || 3000;
    app.listen(port, '0.0.0.0', () => console.log(JSON.stringify({ level: 'info', msg: 'KwanzaLink a ouvir', port })));
  }).catch(e => { console.error('Falha ao iniciar:', e.message); process.exit(1); });
}
module.exports = { createApp, migrate };
