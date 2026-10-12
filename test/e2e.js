const { JSDOM, VirtualConsole } = require('jsdom');
const { createApp, migrate } = require('../server');
const { Pool } = require('pg');
const sl = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const pool = new Pool({ connectionString: 'postgres://kl:kl@localhost/kl_test' });
  await pool.query('drop schema public cascade; create schema public;'); await migrate(pool);
  const srv = createApp({ pool, adminEmail: 'chefe@x.pt', noLimit: true }).listen(0); const base = 'http://localhost:' + srv.address().port;
  const errs = [];
  const open = async (path, jar) => {
    const vc = new VirtualConsole(); vc.on('jsdomError', e => { if (!/scrollTo|IntersectionObserver|showModal/.test(e.message)) errs.push(e.message) });
    const dom = await JSDOM.fromURL(base + path, { runScripts: 'dangerously', resources: 'usable', virtualConsole: vc, pretendToBeVisual: true,
      beforeParse(w) { w.IntersectionObserver = class { observe() {} unobserve() {} }; w.scrollTo = () => {}; w.confirm = () => true; w.opened = [];
        w.open = u => w.opened.push(u); w.fetch = async (u, o = {}) => { const r = await fetch(new URL(u, base), { ...o, headers: { ...(o.headers || {}), origin: base, ...(jar.c ? { cookie: jar.c } : {}) } }); const sc = r.headers.get('set-cookie'); if (sc) jar.c = sc.split(';')[0]; return r; };
        Object.defineProperty(w, 'crypto', { value: require('crypto').webcrypto }); } });
    await sl(400); return dom.window;
  };
  const ok = (c, m) => console.log(c ? 'ok   ' : 'FALHA', m);
  const jar = {}; let w = await open('/', jar), d = w.document;
  const go = async h => { w.location.hash = h; await sl(150) };
  const type = (el, v) => { el.value = v; el.dispatchEvent(new w.Event('input', { bubbles: true })) };
  const click = s => d.querySelector(s).dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  const sub = s => d.querySelector(s).dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
  // registo
  await go('#/criar-conta'); click('[data-nx]'); await sl(30);
  type(d.querySelector('#w1'), 'Ana Silva'); type(d.querySelector('#w2'), 'ana_s'); d.querySelector('#w3').value = 'Moda'; d.querySelector('#w3').dispatchEvent(new w.Event('change', { bubbles: true })); type(d.querySelector('#w5'), '244923000111');
  click('[data-nx]'); await sl(30); click('[data-nx]'); click('[data-nx]'); type(d.querySelector('#w6'), 'ana@x.pt'); type(d.querySelector('#w7'), 'segredo123'); click('[data-nx]'); await sl(500);
  ok(w.location.hash === '#/dashboard', 'registo no servidor e entrada no dashboard (' + w.location.hash + ')');
  const u = (await pool.query("select pw_hash,doc from users where email='ana@x.pt'")).rows[0];
  ok(u && /^\$2/.test(u.pw_hash) && u.doc.page.user === 'ana_s', 'conta na base de dados com hash bcrypt');
  ok(!JSON.stringify(w.localStorage).includes('segredo123'), 'palavra-passe não fica no navegador');
  // produto
  await go('#/dashboard/produtos'); click('#nw'); d.querySelector('#f_title').value = 'Guia 30 dias'; d.querySelector('#f_price').value = '7500'; sub('#df'); await sl(1200);
  const row = (await pool.query("select doc from users where email='ana@x.pt'")).rows[0];
  ok(row.doc.products.length === 1, 'produto guardado no PostgreSQL');
  const snap = (await pool.query("select snapshot from public_pages where username='ana_s'")).rows[0];
  ok(snap && JSON.stringify(snap.snapshot).includes('Guia 30 dias'), 'página pública publicada com o produto');
  // visitante no link curto
  const jar2 = {}; const w2 = await open('/ana_s', jar2); await sl(400);
  const pub = w2.document.querySelector('.phone.pub');
  ok(pub && pub.textContent.includes('Guia 30 dias'), 'link curto /ana_s mostra a página sem login');
  const btn = w2.document.querySelector('.phone.pub a.bt[data-ord]'); btn.dispatchEvent(new w2.MouseEvent('click', { bubbles: true, cancelable: true })); await sl(200);
  const f = w2.document.querySelector('#ordf'); ok(!!f, 'pedido abre formulário');
  w2.document.querySelector('#o1').value = 'João Pedro'; w2.document.querySelector('#o2').value = '244911222333';
  f.dispatchEvent(new w2.Event('submit', { bubbles: true, cancelable: true })); await sl(500);
  ok((await pool.query("select count(*)::int n from inbox")).rows[0].n === 1, 'pedido do visitante gravado no servidor');
  ok(w2.opened.some(u => /wa\.me\/244923000111/.test(u)), 'visitante segue para o WhatsApp do criador');
  // criador recebe
  w.dispatchEvent(new w.Event('focus')); await sl(900);
  await go('#/dashboard/pedidos'); ok(d.querySelector('#ls').textContent.includes('João Pedro'), 'pedido aparece em Pedidos do criador');
  await sl(1200); ok((await pool.query("select count(*)::int n from inbox where delivered_at is not null")).rows[0].n === 1, 'entrega confirmada (ack)');
  await go('#/dashboard/analytics'); await sl(400);
  ok(/Visitas \(30 dias\)\s*[1-9]/.test(d.querySelector('#vis').textContent), 'analytics reais: visitas e cliques (' + d.querySelector('#vis').textContent.replace(/\s+/g, ' ').slice(0, 70) + ')');
  // novo dispositivo (login)
  const jar3 = {}; const w3 = await open('/', jar3); const d3 = w3.document; w3.location.hash = '#/entrar'; await sl(200);
  d3.querySelector('#l1').value = 'ana@x.pt'; d3.querySelector('#l2').value = 'segredo123'; d3.querySelector('#lf').dispatchEvent(new w3.Event('submit', { bubbles: true, cancelable: true })); await sl(600);
  w3.location.hash = '#/dashboard/produtos'; await sl(300);
  ok(d3.querySelector('#ls').textContent.includes('Guia 30 dias'), 'noutro dispositivo: login e dados iguais');
  // administração
  const jar4 = {}; w = await open('/', jar4); d = w.document;
  await go('#/criar-conta'); click('[data-nx]'); await sl(30); type(d.querySelector('#w1'), 'Chefe'); type(d.querySelector('#w2'), 'chefe_k'); d.querySelector('#w3').value = 'Moda'; d.querySelector('#w3').dispatchEvent(new w.Event('change', { bubbles: true }));
  click('[data-nx]'); await sl(30); click('[data-nx]'); click('[data-nx]'); type(d.querySelector('#w6'), 'chefe@x.pt'); type(d.querySelector('#w7'), 'segredo123'); click('[data-nx]'); await sl(500);
  await go('#/admin/utilizadores'); await sl(500); ok(d.querySelector('#adm').textContent.includes('ana@x.pt'), 'administração lista todas as contas');
  await go('#/admin/taxas'); type(d.querySelector('#t1'), '6'); d.querySelector('#tf').dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true })); await sl(400);
  ok((await pool.query("select value from settings where key='fee'")).rows[0].value == 6, 'comissão guardada no servidor');
  console.log('ERROS JS', errs); srv.close(); await pool.end(); process.exit(0);
})();
