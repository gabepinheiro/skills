# Referência - Fastify + Better-Auth

## Database Adapters

Better-Auth suporta múltiplos adapters de banco de dados:

### Prisma

```bash
bun add @prisma/client
bun add -D prisma
```

```typescript
import { prismaAdapter } from "better-auth/adapters/prisma";
import { prisma } from "./prisma";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql", // 'mysql', 'sqlite', 'mongodb'
  }),
});
```

### Drizzle

```bash
bun add drizzle-orm
```

```typescript
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { db } from "./db";

export const auth = betterAuth({
  database: drizzleAdapter(db, {
    provider: "pg", // 'mysql', 'sqlite'
  }),
});
```

### Kysely

```bash
bun add kysely
```

```typescript
import { kyselyAdapter } from "better-auth/adapters/kysely";
import { db } from "./db";

export const auth = betterAuth({
  database: kyselyAdapter(db),
});
```

## Plugin: Username Authentication

O plugin `username` permite usar usernames ao invés de (ou junto com) emails para autenticação.

### Instalação

```typescript
import { betterAuth } from "better-auth";
import { username } from "better-auth/plugins";

export const auth = betterAuth({
  // ... database config

  plugins: [
    username({
      // Permitir login com username OU email
      usernameOrEmail: true,

      // Apenas username (desabilita email)
      // usernameOrEmail: false,

      // Validação customizada do username
      validateUsername: (username: string) => {
        if (username.length < 3) {
          throw new Error("Username must be at least 3 characters");
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
          throw new Error(
            "Username can only contain letters, numbers, and underscores",
          );
        }
        return true;
      },
    }),
  ],
});
```

### Schema do Banco

Adicione o campo `username` ao modelo User:

```prisma
model User {
  id            String    @id @default(cuid())
  email         String?   @unique  // Opcional se usar apenas username
  emailVerified Boolean   @default(false)
  username      String?   @unique  // Campo username
  name          String?
  image         String?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt

  sessions      Session[]
  accounts      Account[]

  @@index([username])
}
```

### Endpoints Modificados

Com o plugin username, os endpoints mudam ligeiramente:

```typescript
// Sign up com username
POST /api/auth/sign-up
Body: {
  username: string,
  email?: string,      // Opcional se usernameOrEmail: false
  password: string,
  name?: string
}

// Sign in com username ou email
POST /api/auth/sign-in
Body: {
  usernameOrEmail: string,  // Aceita username ou email
  password: string
}

// Ou sign in apenas com username
POST /api/auth/sign-in
Body: {
  username: string,
  password: string
}
```

### Helpers de Username

```typescript
// Verificar se username está disponível
export async function isUsernameAvailable(username: string): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { username },
    select: { id: true },
  });

  return !user;
}

// Sugerir username baseado no nome
export function suggestUsername(name: string): string {
  const base = name
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "")
    .slice(0, 15);

  const random = Math.floor(Math.random() * 1000);
  return `${base}${random}`;
}

// Validar formato do username
export function validateUsernameFormat(username: string): {
  valid: boolean;
  error?: string;
} {
  if (username.length < 3) {
    return { valid: false, error: "Username must be at least 3 characters" };
  }

  if (username.length > 20) {
    return { valid: false, error: "Username is too long (max 20 characters)" };
  }

  if (!/^[a-zA-Z]/.test(username)) {
    return { valid: false, error: "Username must start with a letter" };
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return {
      valid: false,
      error: "Username can only contain letters, numbers, and underscores",
    };
  }

  // Lista de usernames reservados
  const reserved = ["admin", "root", "system", "api", "auth", "user"];
  if (reserved.includes(username.toLowerCase())) {
    return { valid: false, error: "This username is reserved" };
  }

  return { valid: true };
}
```

### Rota de Verificação

```typescript
fastify.get<{
  Querystring: { username: string };
}>(
  "/auth/check-username",
  {
    schema: {
      description: "Check username availability",
      tags: ["auth"],
      querystring: {
        type: "object",
        required: ["username"],
        properties: {
          username: { type: "string", minLength: 3, maxLength: 20 },
        },
      },
      response: {
        200: {
          type: "object",
          properties: {
            available: { type: "boolean" },
            username: { type: "string" },
            suggestions: {
              type: "array",
              items: { type: "string" },
            },
          },
        },
      },
    },
  },
  async (request, reply) => {
    const { username } = request.query;

    const validation = validateUsernameFormat(username);
    if (!validation.valid) {
      return reply.status(400).send({
        error: "Invalid username",
        message: validation.error,
      });
    }

    const available = await isUsernameAvailable(username);

    const response: any = {
      available,
      username,
    };

    // Se não disponível, sugerir alternativas
    if (!available) {
      response.suggestions = [
        `${username}${Math.floor(Math.random() * 100)}`,
        `${username}_${Math.floor(Math.random() * 1000)}`,
        `${username}${new Date().getFullYear()}`,
      ];
    }

    return response;
  },
);
```

## Plugin: Organizations

O plugin `organization` adiciona suporte completo a multi-tenancy, permitindo que usuários criem e gerenciem organizações com membros e permissões.

### Instalação

```typescript
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";

export const auth = betterAuth({
  // ... database config

  plugins: [
    organization({
      // Permitir usuários criarem organizações
      allowUserToCreateOrganization: true,

      // Limite de organizações por usuário
      maxOrganizationsPerUser: 5,

      // Roles disponíveis
      roles: ["owner", "admin", "member"],

      // Permissões disponíveis
      permissions: [
        "organization:read",
        "organization:update",
        "organization:delete",
        "member:invite",
        "member:remove",
        "member:update-role",
        "project:create",
        "project:read",
        "project:update",
        "project:delete",
      ],

      // Mapeamento de permissões por role
      rolePermissions: {
        owner: ["*"], // Todas as permissões
        admin: [
          "organization:read",
          "organization:update",
          "member:invite",
          "member:remove",
          "member:update-role",
          "project:create",
          "project:read",
          "project:update",
          "project:delete",
        ],
        member: ["organization:read", "project:read"],
      },

      // Callback ao criar organização
      async onOrganizationCreate({ organization, userId }) {
        console.log(`Organization created: ${organization.name} by ${userId}`);

        // Criar recursos iniciais
        await createDefaultProjects(organization.id);
      },

      // Callback ao adicionar membro
      async onMemberAdded({ organization, member }) {
        console.log(`Member ${member.userId} added to ${organization.name}`);

        // Enviar email de boas-vindas
        await sendWelcomeToOrgEmail(member);
      },
    }),
  ],
});
```

### Schema do Banco

```prisma
model Organization {
  id        String   @id @default(cuid())
  name      String
  slug      String   @unique
  logo      String?
  metadata  Json?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  members   OrganizationMember[]
  invites   OrganizationInvite[]

  @@index([slug])
}

model OrganizationMember {
  id             String       @id @default(cuid())
  organizationId String
  userId         String
  role           String       // owner, admin, member
  createdAt      DateTime     @default(now())

  organization   Organization @relation(fields: [organizationId], references: [id], onDelete: Cascade)
  user           User         @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([organizationId, userId])
  @@index([userId])
  @@index([organizationId])
}

model OrganizationInvite {
  id             String       @id @default(cuid())
  organizationId String
  email          String
  role           String
  invitedBy      String
  expiresAt      DateTime
  status         String       // pending, accepted, expired, revoked
  token          String       @unique
  createdAt      DateTime     @default(now())

  organization   Organization @relation(fields: [organizationId], references: [id], onDelete: Cascade)

  @@unique([organizationId, email])
  @@index([email])
  @@index([token])
}

// Adicionar ao User
model User {
  // ... campos existentes

  organizationMembers OrganizationMember[]
}
```

### Endpoints Automáticos

```typescript
// Criar organização
POST /api/auth/organization/create
Body: { name: string, slug: string, logo?: string, metadata?: object }

// Listar organizações do usuário
GET /api/auth/organization/list

// Obter organização
GET /api/auth/organization/:organizationId

// Atualizar organização
PATCH /api/auth/organization/:organizationId
Body: { name?: string, slug?: string, logo?: string, metadata?: object }

// Deletar organização
DELETE /api/auth/organization/:organizationId

// Convidar membro
POST /api/auth/organization/:organizationId/invite
Body: { email: string, role: string }

// Aceitar convite
POST /api/auth/organization/invite/accept
Body: { inviteId: string }

// Listar convites pendentes
GET /api/auth/organization/invites

// Revogar convite
DELETE /api/auth/organization/invite/:inviteId

// Listar membros
GET /api/auth/organization/:organizationId/members

// Atualizar role de membro
PATCH /api/auth/organization/:organizationId/members/:userId
Body: { role: string }

// Remover membro
DELETE /api/auth/organization/:organizationId/members/:userId

// Sair da organização
POST /api/auth/organization/:organizationId/leave

// Transferir ownership
POST /api/auth/organization/:organizationId/transfer
Body: { newOwnerId: string }

// Verificar permissão
POST /api/auth/organization/:organizationId/has-permission
Body: { permission: string }
```

### API Helpers

```typescript
// Verificar se usuário é membro
const isMember = await auth.api.organization.isMember({
  organizationId: "org-id",
  userId: "user-id",
});

// Obter role do usuário
const member = await auth.api.organization.getMember({
  organizationId: "org-id",
  userId: "user-id",
});
console.log(member?.role); // "owner" | "admin" | "member"

// Verificar permissão
const hasPermission = await auth.api.organization.hasPermission({
  organizationId: "org-id",
  userId: "user-id",
  permission: "project:create",
});

// Listar organizações do usuário
const orgs = await auth.api.organization.list({
  userId: "user-id",
});

// Listar membros da organização
const members = await auth.api.organization.listMembers({
  organizationId: "org-id",
});

// Convidar membro
const invite = await auth.api.organization.invite({
  organizationId: "org-id",
  email: "user@example.com",
  role: "member",
  invitedBy: "inviter-user-id",
});

// Atualizar role
await auth.api.organization.updateMemberRole({
  organizationId: "org-id",
  userId: "user-id",
  role: "admin",
});

// Remover membro
await auth.api.organization.removeMember({
  organizationId: "org-id",
  userId: "user-id",
});
```

### Hierarquia de Roles

```typescript
// Verificar se role tem autoridade sobre outra
function hasAuthority(userRole: string, targetRole: string): boolean {
  const hierarchy = {
    owner: 3,
    admin: 2,
    member: 1,
  };

  return (
    hierarchy[userRole as keyof typeof hierarchy] >
    hierarchy[targetRole as keyof typeof hierarchy]
  );
}

// Exemplo: apenas roles superiores podem remover membros
if (!hasAuthority(currentUserRole, targetUserRole)) {
  throw new Error("Cannot remove user with equal or higher role");
}
```

### Scoped Resources

Vincule recursos a organizações:

```prisma
model Project {
  id             String       @id @default(cuid())
  name           String
  organizationId String
  createdBy      String
  createdAt      DateTime     @default(now())

  organization   Organization @relation(fields: [organizationId], references: [id], onDelete: Cascade)
  creator        User         @relation(fields: [createdBy], references: [id])

  @@index([organizationId])
}
```

```typescript
// Criar projeto na organização
fastify.post<{
  Params: { organizationId: string };
  Body: { name: string };
}>(
  "/organizations/:organizationId/projects",
  {
    preHandler: [requireOrganization({ permission: "project:create" })],
  },
  async (request, reply) => {
    const { name } = request.body;

    const project = await prisma.project.create({
      data: {
        name,
        organizationId: request.organization!.id,
        createdBy: request.user!.id,
      },
    });

    return project;
  },
);
```

### Context Switching

Permitir usuário trocar de organização ativa:

```typescript
// Adicionar organizationId à sessão
declare module "fastify" {
  interface FastifyRequest {
    activeOrganization?: string;
  }
}

// Middleware para definir organização ativa
fastify.addHook("onRequest", async (request, reply) => {
  const orgId = request.headers["x-organization-id"] as string;

  if (orgId && request.user) {
    const isMember = await auth.api.organization.isMember({
      organizationId: orgId,
      userId: request.user.id,
    });

    if (isMember) {
      request.activeOrganization = orgId;
    }
  }
});
```

## OAuth Providers

Better-Auth suporta múltiplos provedores OAuth:

### Configuração Base

```typescript
import { betterAuth } from "better-auth";

export const auth = betterAuth({
  // ... configuração base

  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      redirectURI: `${process.env.BETTER_AUTH_URL}/api/auth/callback/google`,
    },

    github: {
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      redirectURI: `${process.env.BETTER_AUTH_URL}/api/auth/callback/github`,
    },

    discord: {
      clientId: process.env.DISCORD_CLIENT_ID!,
      clientSecret: process.env.DISCORD_CLIENT_SECRET!,
      redirectURI: `${process.env.BETTER_AUTH_URL}/api/auth/callback/discord`,
    },

    microsoft: {
      clientId: process.env.MICROSOFT_CLIENT_ID!,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
      redirectURI: `${process.env.BETTER_AUTH_URL}/api/auth/callback/microsoft`,
      tenant: "common", // ou ID do tenant específico
    },
  },
});
```

### Endpoints OAuth Automáticos

Better-Auth cria automaticamente endpoints para OAuth:

```typescript
// Iniciar OAuth flow
GET /api/auth/signin/google
GET /api/auth/signin/github
GET /api/auth/signin/discord

// Callback após autorização
GET /api/auth/callback/google
GET /api/auth/callback/github
GET /api/auth/callback/discord

// Desvincular conta
POST /api/auth/unlink/:provider
```

### Uso no Frontend

```typescript
import { authClient } from "./lib/auth-client";

// Redirecionar para OAuth
async function signInWithGoogle() {
  await authClient.signIn.social({
    provider: "google",
    callbackURL: "/dashboard",
  });
}

// Vincular conta adicional
async function linkGithub() {
  await authClient.linkSocial({
    provider: "github",
  });
}

// Desvincular
async function unlinkProvider(provider: string) {
  await authClient.unlinkSocial({
    provider,
  });
}
```

## Two-Factor Authentication (2FA)

Configure autenticação de dois fatores:

```typescript
import { betterAuth } from "better-auth";

export const auth = betterAuth({
  // ... configuração base

  twoFactor: {
    enabled: true,
    issuer: "MyApp",

    // TOTP (Time-based OTP - Google Authenticator, Authy, etc)
    totp: {
      enabled: true,
      window: 1, // Aceitar códigos de ±30s
      digits: 6,
      period: 30,
    },

    // Backup codes
    backupCodes: {
      enabled: true,
      length: 8,
      count: 10,
    },
  },
});
```

### Endpoints 2FA

```typescript
// Gerar QR code para TOTP
POST /api/auth/2fa/generate

// Ativar 2FA
POST /api/auth/2fa/enable
Body: { code: string }

// Desativar 2FA
POST /api/auth/2fa/disable
Body: { password: string }

// Verificar código 2FA no login
POST /api/auth/2fa/verify
Body: { code: string }

// Gerar backup codes
POST /api/auth/2fa/backup-codes/generate

// Usar backup code
POST /api/auth/2fa/backup-codes/verify
Body: { code: string }
```

### Implementação no Fastify

```typescript
fastify.post(
  "/auth/2fa/setup",
  {
    preHandler: [requireAuth],
  },
  async (request, reply) => {
    const result = await auth.api.twoFactor.generate({
      userId: request.user!.id,
    });

    return {
      secret: result.secret,
      qrCode: result.qrCode,
      backupCodes: result.backupCodes,
    };
  },
);

fastify.post<{
  Body: { code: string };
}>(
  "/auth/2fa/verify",
  {
    preHandler: [requireAuth],
  },
  async (request, reply) => {
    const { code } = request.body;

    const verified = await auth.api.twoFactor.verify({
      userId: request.user!.id,
      code,
    });

    if (!verified) {
      return reply.status(400).send({
        error: "Invalid code",
        message: "The 2FA code is incorrect",
      });
    }

    return { message: "2FA verified successfully" };
  },
);
```

## Email Verification

Configure verificação de email:

```typescript
import { betterAuth } from "better-auth";

export const auth = betterAuth({
  // ... configuração base

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: true,

    sendVerificationEmail: async ({ email, token, url }) => {
      await sendEmail({
        to: email,
        subject: "Verify your email",
        html: `
          <h1>Verify your email</h1>
          <p>Click the link below to verify your email:</p>
          <a href="${url}">Verify Email</a>
          <p>Or use this code: ${token}</p>
        `,
      });
    },
  },
});
```

### Endpoints de Verificação

```typescript
// Enviar email de verificação
POST / api / auth / send - verification - email;

// Verificar email com token
POST / api / auth / verify - email;
Body: {
  token: string;
}

// Reenviar email de verificação
POST / api / auth / resend - verification - email;
```

### Configurar SMTP

```typescript
// lib/email.ts
import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

export async function sendEmail({
  to,
  subject,
  html,
}: {
  to: string;
  subject: string;
  html: string;
}) {
  await transporter.sendMail({
    from: process.env.SMTP_FROM || "noreply@example.com",
    to,
    subject,
    html,
  });
}
```

## Password Reset

Configure reset de senha:

```typescript
export const auth = betterAuth({
  // ... configuração base

  emailAndPassword: {
    enabled: true,

    resetPassword: {
      sendResetEmail: async ({ email, token, url }) => {
        await sendEmail({
          to: email,
          subject: "Reset your password",
          html: `
            <h1>Reset your password</h1>
            <p>Click the link below to reset your password:</p>
            <a href="${url}">Reset Password</a>
            <p>This link expires in 1 hour.</p>
          `,
        });
      },
      tokenExpiresIn: 60 * 60, // 1 hora
    },
  },
});
```

### Fluxo de Reset

```typescript
// 1. Solicitar reset
POST /api/auth/forgot-password
Body: { email: string }

// 2. Resetar com token
POST /api/auth/reset-password
Body: { token: string, password: string }
```

## Session Management

Configurações avançadas de sessão:

```typescript
export const auth = betterAuth({
  // ... configuração base

  session: {
    // Expiração da sessão
    expiresIn: 60 * 60 * 24 * 7, // 7 dias

    // Atualizar sessão automaticamente
    updateAge: 60 * 60 * 24, // Atualiza a cada 24h

    // Cookie cache para performance
    cookieCache: {
      enabled: true,
      maxAge: 60 * 5, // 5 minutos
    },

    // Múltiplas sessões por usuário
    multiSession: true,

    // Limitar sessões simultâneas
    maxSessions: 5,

    // Informações da sessão
    storeSessionMetadata: {
      ipAddress: true,
      userAgent: true,
      location: false, // Requer serviço de geolocation
    },
  },
});
```

### Gerenciar Sessões

```typescript
// Listar todas as sessões
const sessions = await auth.api.listSessions({
  userId: "user-id",
});

// Revogar sessão específica
await auth.api.revokeSession({
  sessionId: "session-id",
});

// Revogar todas as sessões exceto a atual
await auth.api.revokeOtherSessions({
  sessionId: "current-session-id",
  userId: "user-id",
});

// Revogar todas as sessões
await auth.api.revokeAllSessions({
  userId: "user-id",
});
```

## Rate Limiting Integrado

Better-Auth tem rate limiting nativo:

```typescript
export const auth = betterAuth({
  // ... configuração base

  rateLimit: {
    enabled: true,

    // Limite global
    window: 60 * 1000, // 1 minuto
    max: 100, // 100 requisições por minuto

    // Limites específicos por endpoint
    customLimits: {
      "/api/auth/sign-in": {
        window: 15 * 60 * 1000, // 15 minutos
        max: 5, // 5 tentativas
      },
      "/api/auth/sign-up": {
        window: 60 * 60 * 1000, // 1 hora
        max: 3, // 3 registros
      },
      "/api/auth/forgot-password": {
        window: 60 * 60 * 1000, // 1 hora
        max: 3, // 3 solicitações
      },
    },

    // Storage (redis para produção distribuída)
    storage: "memory", // ou 'redis'
  },
});
```

## Hooks e Callbacks

Better-Auth oferece hooks para customização:

```typescript
export const auth = betterAuth({
  // ... configuração base

  callbacks: {
    // Após sign up
    async onSignUp({ user, session }) {
      console.log("New user signed up:", user.email);

      // Enviar email de boas-vindas
      await sendWelcomeEmail(user.email);

      // Criar perfil inicial
      await createUserProfile(user.id);
    },

    // Após sign in
    async onSignIn({ user, session }) {
      console.log("User signed in:", user.email);

      // Atualizar último login
      await updateLastLogin(user.id);
    },

    // Antes de criar sessão
    async beforeSession({ user, session }) {
      // Verificar se usuário está banido
      if (user.isBanned) {
        throw new Error("User is banned");
      }

      return { user, session };
    },

    // Após criar sessão
    async afterSession({ user, session }) {
      // Log de auditoria
      await logSession(user.id, session.id);
    },
  },
});
```

## Plugins e Extensões

Better-Auth é extensível com plugins:

```typescript
import { betterAuth } from "better-auth";
import { twoFactorPlugin } from "better-auth/plugins/two-factor";
import { adminPlugin } from "better-auth/plugins/admin";
import { organizationsPlugin } from "better-auth/plugins/organizations";

export const auth = betterAuth({
  // ... configuração base

  plugins: [
    twoFactorPlugin({
      issuer: "MyApp",
    }),

    adminPlugin({
      impersonation: true, // Admins podem se passar por outros usuários
    }),

    organizationsPlugin({
      allowUserToCreateOrganization: true,
      maxOrganizationsPerUser: 5,
    }),
  ],
});
```

## Segurança Avançada

### Password Policies

```typescript
export const auth = betterAuth({
  // ... configuração base

  emailAndPassword: {
    enabled: true,

    password: {
      minLength: 12,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,

      // Prevenir senhas comuns
      checkCommonPasswords: true,

      // Prevenir reutilização
      preventReuse: 5, // Últimas 5 senhas
    },
  },
});
```

### Account Lockout

```typescript
export const auth = betterAuth({
  // ... configuração base

  accountLockout: {
    enabled: true,
    maxAttempts: 5,
    duration: 15 * 60, // 15 minutos

    // Aumentar tempo de bloqueio progressivamente
    progressive: true,
  },
});
```

### CAPTCHA Integration

```typescript
export const auth = betterAuth({
  // ... configuração base

  captcha: {
    enabled: true,
    provider: "recaptcha", // ou 'hcaptcha', 'turnstile'

    siteKey: process.env.RECAPTCHA_SITE_KEY!,
    secretKey: process.env.RECAPTCHA_SECRET_KEY!,

    // Endpoints que requerem captcha
    requiredFor: ["sign-up", "sign-in", "forgot-password"],

    // Score mínimo (reCAPTCHA v3)
    minimumScore: 0.5,
  },
});
```

## Logging e Auditoria

Configure logging de eventos de autenticação:

```typescript
export const auth = betterAuth({
  // ... configuração base

  audit: {
    enabled: true,

    events: [
      "sign-up",
      "sign-in",
      "sign-out",
      "password-change",
      "email-verification",
      "password-reset",
      "2fa-enabled",
      "2fa-disabled",
      "account-deleted",
    ],

    store: async (event) => {
      await prisma.auditLog.create({
        data: {
          userId: event.userId,
          action: event.action,
          ipAddress: event.ipAddress,
          userAgent: event.userAgent,
          metadata: event.metadata,
          timestamp: new Date(),
        },
      });
    },
  },
});
```

## Testing

Configure Better-Auth para testes:

```typescript
// test/setup.ts
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

export const testAuth = betterAuth({
  database: memoryAdapter(), // Banco em memória para testes

  secret: "test-secret-key-32-chars-min",
  baseURL: "http://localhost:3000",

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false, // Desabilitar para testes
  },

  session: {
    expiresIn: 60 * 60, // 1 hora para testes
  },
});

// Helper para criar usuário de teste
export async function createTestUser(overrides = {}) {
  return await testAuth.api.signUp({
    email: "test@example.com",
    password: "Test123!@#",
    name: "Test User",
    ...overrides,
  });
}
```

## Environment Variables Reference

```bash
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/mydb"

# Better-Auth Core
BETTER_AUTH_SECRET="your-secret-min-32-chars"
BETTER_AUTH_URL="http://localhost:3000"

# Cookies
COOKIE_SECRET="your-cookie-secret"

# Frontend
FRONTEND_URL="http://localhost:5173"

# SMTP (Email)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_SECURE="false"
SMTP_USER="your-email@gmail.com"
SMTP_PASSWORD="your-app-password"
SMTP_FROM="noreply@example.com"

# OAuth Providers
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"

GITHUB_CLIENT_ID="your-github-client-id"
GITHUB_CLIENT_SECRET="your-github-client-secret"

DISCORD_CLIENT_ID="your-discord-client-id"
DISCORD_CLIENT_SECRET="your-discord-client-secret"

# reCAPTCHA
RECAPTCHA_SITE_KEY="your-site-key"
RECAPTCHA_SECRET_KEY="your-secret-key"

# Redis (para rate limiting distribuído)
REDIS_URL="redis://localhost:6379"
```

## OpenAPI/Swagger Documentation

Better-Auth possui o método `generateOpenAPISchema()` que gera automaticamente a documentação OpenAPI de todos os endpoints.

### Gerar Schema Automaticamente

```typescript
import { auth } from "./lib/auth";

// Gerar schema OpenAPI
const openAPISchema = await auth.api.generateOpenAPISchema();

console.log(openAPISchema);
// Retorna um objeto OpenAPI 3.0 completo com:
// - Todos os endpoints do Better-Auth
// - Endpoints adicionados por plugins
// - Schemas de request/response
// - Security schemes
```

### Integrar com Fastify Swagger

```typescript
import Fastify from "fastify";
import swagger from "@fastify/swagger";
import scalar from "@scalar/fastify-api-reference";
import { auth } from "./lib/auth";

const fastify = Fastify();

// Gerar schema do Better-Auth
const betterAuthSchema = await auth.api.generateOpenAPISchema();

// Usar diretamente no Swagger
await fastify.register(swagger, {
  openapi: betterAuthSchema,
});

// Registrar Scalar UI
await fastify.register(scalar, {
  routePrefix: "/docs",
});

// Montar rotas do Better-Auth
fastify.all("/api/auth/*", async (request, reply) => {
  return auth.handler(request.raw, reply.raw);
});
```

### Mesclar com Endpoints Customizados

Use um helper para combinar o schema do Better-Auth com seus endpoints:

```typescript
import { OpenAPIV3 } from "openapi-types";

function mergeOpenAPISchemas(
  betterAuthSchema: OpenAPIV3.Document,
  customSchema: Partial<OpenAPIV3.Document>,
): OpenAPIV3.Document {
  return {
    openapi: betterAuthSchema.openapi,
    info: {
      ...betterAuthSchema.info,
      ...customSchema.info,
    },
    servers: customSchema.servers || betterAuthSchema.servers || [],
    paths: {
      ...betterAuthSchema.paths,
      ...(customSchema.paths || {}),
    },
    components: {
      schemas: {
        ...betterAuthSchema.components?.schemas,
        ...customSchema.components?.schemas,
      },
      securitySchemes: {
        ...betterAuthSchema.components?.securitySchemes,
        ...customSchema.components?.securitySchemes,
      },
    },
    tags: [...(betterAuthSchema.tags || []), ...(customSchema.tags || [])],
  };
}

// Uso
const betterAuthSchema = await auth.api.generateOpenAPISchema();

const customSchema = {
  info: {
    title: "My API",
    version: "1.0.0",
  },
  tags: [{ name: "users", description: "User management" }],
  paths: {
    "/api/users": {
      get: {
        tags: ["users"],
        summary: "List users",
        responses: {
          "200": {
            description: "Success",
            content: {
              "application/json": {
                schema: { type: "array", items: { type: "object" } },
              },
            },
          },
        },
      },
    },
  },
};

const merged = mergeOpenAPISchemas(betterAuthSchema, customSchema);

await fastify.register(swagger, {
  openapi: merged,
});
```

### Estratégias de Documentação Manual (Alternativa)

Se preferir não usar `generateOpenAPISchema()`, pode documentar manualmente:

#### 1. Documentação Inline

```typescript
fastify.route({
  method: "POST",
  url: "/api/auth/sign-up",
  schema: {
    description: "Register a new user",
    tags: ["auth"],
    body: {
      type: "object",
      required: ["email", "password"],
      properties: {
        email: { type: "string", format: "email" },
        password: { type: "string", minLength: 8 },
        name: { type: "string" },
      },
    },
    response: {
      200: {
        type: "object",
        properties: {
          user: { type: "object" },
          session: { type: "object" },
        },
      },
    },
  },
  handler: async (req, reply) => auth.handler(req.raw, reply.raw),
});
```

#### 2. Schemas Centralizados (Recomendado para muitos endpoints)

```typescript
// schemas/openapi.ts
export const authSchemas = {
  SignUpRequest: {
    type: "object",
    required: ["email", "password"],
    properties: {
      email: { type: "string", format: "email" },
      password: { type: "string", minLength: 8 },
      name: { type: "string" },
    },
  },
  // ... outros schemas
};

// No swagger config
await fastify.register(swagger, {
  openapi: {
    components: {
      schemas: authSchemas,
    },
  },
});

// Uso
fastify.route({
  schema: {
    body: { $ref: "#/components/schemas/SignUpRequest" },
  },
  // ...
});
```

#### 3. Generator Automático (Avançado)

Crie um helper que registra rotas Better-Auth com schemas:

```typescript
// lib/better-auth-openapi.ts
import { FastifyInstance } from "fastify";

interface AuthRoute {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  description: string;
  body?: object;
  response?: object;
  security?: boolean;
}

const authRoutes: AuthRoute[] = [
  {
    method: "POST",
    path: "/api/auth/sign-up",
    description: "Register new user",
    body: {
      type: "object",
      required: ["email", "password"],
      properties: {
        email: { type: "string", format: "email" },
        password: { type: "string", minLength: 8 },
        name: { type: "string" },
      },
    },
    response: {
      200: { type: "object" },
      400: { type: "object" },
    },
  },
  {
    method: "POST",
    path: "/api/auth/sign-in",
    description: "Authenticate user",
    body: {
      type: "object",
      required: ["email", "password"],
      properties: {
        email: { type: "string" },
        password: { type: "string" },
      },
    },
    response: {
      200: { type: "object" },
      401: { type: "object" },
    },
  },
  {
    method: "POST",
    path: "/api/auth/sign-out",
    description: "Sign out user",
    security: true,
    response: {
      200: { type: "object" },
    },
  },
  {
    method: "GET",
    path: "/api/auth/session",
    description: "Get current session",
    security: true,
    response: {
      200: { type: "object" },
      401: { type: "object" },
    },
  },
  // ... adicionar mais rotas
];

export function registerBetterAuthWithOpenAPI(
  fastify: FastifyInstance,
  authHandler: any,
) {
  for (const route of authRoutes) {
    const schema: any = {
      description: route.description,
      tags: ["auth"],
    };

    if (route.body) schema.body = route.body;
    if (route.response) schema.response = route.response;
    if (route.security) {
      schema.security = [{ sessionToken: [] }, { bearerAuth: [] }];
    }

    fastify.route({
      method: route.method,
      url: route.path,
      schema,
      handler: async (request, reply) => {
        return authHandler(request.raw, reply.raw);
      },
    });
  }

  // Catch-all para rotas não documentadas
  fastify.all("/api/auth/*", async (request, reply) => {
    return authHandler(request.raw, reply.raw);
  });
}

// Uso
import { auth } from "./auth";
registerBetterAuthWithOpenAPI(fastify, auth.handler);
```

### Security Schemes

Configure diferentes métodos de autenticação:

```typescript
await fastify.register(swagger, {
  openapi: {
    components: {
      securitySchemes: {
        // Cookie-based (browser)
        sessionToken: {
          type: "apiKey",
          in: "cookie",
          name: "better-auth.session_token",
          description: "Session cookie (sent automatically by browser)",
        },

        // Bearer token (API clients)
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "SessionToken",
          description: "Session token in Authorization header",
        },

        // API Key (se implementado)
        apiKey: {
          type: "apiKey",
          in: "header",
          name: "X-API-Key",
          description: "API key for server-to-server",
        },
      },
    },
  },
});
```

### Documentação de Erros

Documente respostas de erro consistentemente:

```typescript
const errorResponses = {
  400: {
    description: "Bad Request",
    content: {
      "application/json": {
        schema: {
          type: "object",
          properties: {
            error: { type: "string", example: "Validation error" },
            message: { type: "string" },
            details: { type: "array", items: { type: "object" } },
          },
        },
      },
    },
  },
  401: {
    description: "Unauthorized",
    content: {
      "application/json": {
        schema: {
          type: "object",
          properties: {
            error: { type: "string", example: "Unauthorized" },
            message: { type: "string", example: "Invalid credentials" },
          },
        },
      },
    },
  },
  403: {
    description: "Forbidden",
    content: {
      "application/json": {
        schema: {
          type: "object",
          properties: {
            error: { type: "string", example: "Forbidden" },
            message: { type: "string" },
          },
        },
      },
    },
  },
  500: {
    description: "Internal Server Error",
    content: {
      "application/json": {
        schema: {
          type: "object",
          properties: {
            error: { type: "string", example: "Internal Server Error" },
            message: { type: "string" },
          },
        },
      },
    },
  },
};

// Uso
fastify.route({
  schema: {
    response: {
      200: {
        /* success schema */
      },
      ...errorResponses,
    },
  },
});
```

### Exemplos de Requisição

Adicione exemplos para melhor UX:

```typescript
fastify.route({
  schema: {
    body: {
      type: "object",
      properties: {
        email: { type: "string" },
        password: { type: "string" },
      },
      examples: [
        {
          email: "user@example.com",
          password: "SecurePass123!",
        },
      ],
    },
  },
});
```

### Tags e Grupos

Organize endpoints em grupos:

```typescript
await fastify.register(swagger, {
  openapi: {
    tags: [
      {
        name: "auth",
        description: "Authentication and authorization",
        externalDocs: {
          description: "Better-Auth Docs",
          url: "https://www.better-auth.com/docs",
        },
      },
      {
        name: "auth:sessions",
        description: "Session management",
      },
      {
        name: "auth:password",
        description: "Password management",
      },
    ],
  },
});

// Uso
fastify.route({
  schema: {
    tags: ["auth:password"],
  },
});
```

### Exportar Spec

Exponha o OpenAPI spec para ferramentas externas:

```typescript
// Endpoint para baixar spec
fastify.get("/docs/openapi.json", async () => {
  return fastify.swagger();
});

// Ou YAML
fastify.get("/docs/openapi.yaml", async (request, reply) => {
  const spec = fastify.swagger();
  const yaml = require("yaml");
  reply.type("text/yaml");
  return yaml.stringify(spec);
});
```

## Performance Tips

1. **Use cookie cache** - Reduz queries ao banco
2. **Configure session.updateAge** - Evita atualizações desnecessárias
3. **Use Redis para rate limiting** - Em ambientes distribuídos
4. **Implemente connection pooling** - Para o adapter do banco
5. **Use índices apropriados** - Nas tabelas de sessão e usuários
6. **Configure maxSessions** - Limite sessões por usuário
7. **Implemente cleanup de sessões** - Job periódico para remover sessões expiradas

```typescript
// Cleanup de sessões expiradas
async function cleanupExpiredSessions() {
  await prisma.session.deleteMany({
    where: {
      expiresAt: {
        lt: new Date(),
      },
    },
  });
}

// Executar diariamente
setInterval(cleanupExpiredSessions, 24 * 60 * 60 * 1000);
```
