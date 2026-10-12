# KwanzaLink — servidor, base de dados e site

Node.js + Express + PostgreSQL. O servidor serve o site (`public/index.html`) e a API em `/api`.

## O que já é real
- Contas com palavra-passe em bcrypt e sessão por cookie HttpOnly (30 dias).
- Dados de cada utilizador guardados em PostgreSQL e acessíveis de qualquer dispositivo.
- Página pública em `/{username}` e media kit em `/#/m/{username}`, sem login.
- Pedidos e marcações feitos por visitantes ficam no servidor e chegam aos Pedidos/Agenda do criador.
- Visitas e cliques medidos (agregados por dia, sem dados pessoais).
- Administração: contas, suspensão, levantamentos, comissão (3–8%) e auditoria. O administrador é a conta com o e-mail definido em `ADMIN_EMAIL`.
- Proteções: limite de pedidos, verificação de origem (CSRF), cabeçalhos de segurança e CSP.

## Ainda não é real
- Pagamentos em Kz: a carteira só faz contas e o levantamento é aprovado manualmente pela administração.
- E-mail de recuperação de palavra-passe e WhatsApp oficial (hoje usa links wa.me).
- Dados de marcas (campanhas, parcerias, afiliados) ainda vivem no documento de cada conta e não são partilhados entre contas.

## Variáveis de ambiente
| Nome | Descrição |
|---|---|
| `DATABASE_URL` | Ligação ao PostgreSQL (obrigatória) |
| `ADMIN_EMAIL` | E-mail da conta administradora |
| `NODE_ENV` | `production` ativa cookies Secure |
| `PGSSL` | `1` se a base de dados exigir SSL |

## Executar localmente
```
npm install
export DATABASE_URL=postgres://utilizador:senha@localhost/kwanzalink
npm start
```
O esquema (`schema.sql`) é criado sozinho no arranque.

## Testes
`npm test` (API, precisa de PostgreSQL em `TEST_DATABASE_URL`) e `npm run test:e2e` (site + servidor).

## Publicar no Render
Crie um repositório no GitHub com estes ficheiros e use **New > Blueprint** com `render.yaml`, ou crie um Web Service (Node) e um PostgreSQL à mão com os comandos de `render.yaml`.
