# Fastify + Better-Auth Skill

Skill para integrar autenticação completa no Fastify usando Better-Auth, uma biblioteca moderna e type-safe para gerenciamento de autenticação e sessões.

## Quando usar esta skill

Esta skill é automaticamente aplicada quando você:

- Mencionar Better-Auth ou authentication
- Implementar login, signup ou logout
- Configurar sessões de usuário
- Proteger rotas com autenticação
- Implementar autorização baseada em roles

## O que esta skill oferece

- **Setup completo**: Configuração do Better-Auth com Fastify
- **Database schemas**: Schemas Prisma para User, Session, Account
- **Middlewares**: Autenticação e autorização prontos para uso
- **Rotas protegidas**: Patterns para proteger endpoints
- **OAuth providers**: Integração com Google, GitHub, Discord, etc
- **2FA**: Autenticação de dois fatores com TOTP
- **Email verification**: Verificação de email com tokens
- **Password reset**: Fluxo completo de recuperação de senha
- **Session management**: Gerenciamento avançado de sessões
- **Rate limiting**: Proteção contra brute force
- **Melhores práticas**: Segurança e performance

## Estrutura da skill

- **SKILL.md**: Setup inicial, configuração básica, middlewares e checklist
- **examples.md**: Exemplo completo de API com autenticação (CRUD protegido)
- **reference.md**: OAuth, 2FA, email verification, configs avançadas

## Arquivos gerados

Ao usar esta skill, você criará uma estrutura como:

```
src/
├── server.ts
├── lib/
│   ├── auth.ts           # Configuração Better-Auth
│   ├── auth-helpers.ts   # Funções auxiliares
│   └── prisma.ts         # Cliente Prisma
├── middleware/
│   └── auth.ts           # Middlewares de autenticação
├── routes/
│   ├── auth.ts           # Rotas de autenticação
│   └── users.ts          # Rotas protegidas
└── schemas/
    └── auth.ts           # Schemas Zod
```

## Principais dependências

```bash
bun add better-auth @fastify/cors @fastify/cookie
bun add @prisma/client
bun add -D prisma
```

## Início rápido

1. **Instalar dependências e configurar banco**
2. **Criar schema Prisma** com tabelas User, Session, Account
3. **Configurar Better-Auth** em `lib/auth.ts`
4. **Integrar com Fastify** montando rotas em `/api/auth/*`
5. **Criar middlewares** de autenticação e autorização
6. **Proteger rotas** usando preHandler

## Endpoints automáticos

Better-Auth cria automaticamente:

```
POST /api/auth/sign-up      # Registro
POST /api/auth/sign-in      # Login
POST /api/auth/sign-out     # Logout
GET  /api/auth/session      # Verificar sessão
GET  /api/auth/list-sessions # Listar sessões
POST /api/auth/revoke-session # Revogar sessão
POST /api/auth/forgot-password # Esqueci senha
POST /api/auth/reset-password  # Resetar senha
```

## Features avançadas

- **Username authentication**: Login com username ao invés de email
- **Organizations**: Multi-tenancy com membros, roles e permissões
- **OAuth**: Google, GitHub, Discord, Microsoft, etc
- **2FA**: TOTP (Google Authenticator) + backup codes
- **Email verification**: Com tokens e links
- **Password policies**: Complexidade, histórico, expiração
- **Account lockout**: Bloqueio após tentativas falhas
- **Session management**: Múltiplas sessões, revogação
- **Audit logs**: Registro de eventos de segurança
- **Rate limiting**: Proteção contra abuse

## Recursos adicionais

- [Better-Auth Documentation](https://www.better-auth.com/)
- [Better-Auth GitHub](https://github.com/better-auth/better-auth)
- [Fastify Documentation](https://www.fastify.io/)
