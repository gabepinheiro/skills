---
name: fastify-better-auth
description: Integrate Better-Auth with Fastify for authentication and session management. Use when implementing authentication, user sessions, login/signup flows, protected routes, or when the user mentions Better-Auth, authentication, login, or session management with Fastify.
---

# Fastify + Better-Auth

Integre autenticação completa no Fastify usando Better-Auth, uma biblioteca moderna e type-safe para gerenciamento de autenticação e sessões.

## Dependências Necessárias

```bash
# Better-Auth e dependências core
bun add better-auth

# Database adapter (exemplo com Prisma)
bun add @prisma/client
bun add -D prisma

# Fastify
bun add fastify @fastify/cors @fastify/cookie
```

## Setup Inicial

### 1. Configurar Better-Auth

Crie o arquivo de configuração do Better-Auth:

```typescript
// lib/auth.ts
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { prisma } from "./prisma";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql", // ou 'mysql', 'sqlite'
  }),
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false, // true em produção
  },
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 dias
    updateAge: 60 * 60 * 24, // atualiza a cada 24h
  },
  secret: process.env.BETTER_AUTH_SECRET!,
  baseURL: process.env.BETTER_AUTH_URL || "http://localhost:3000",
});
```

### 2. Schema do Banco de Dados

Better-Auth requer tabelas específicas. Exemplo com Prisma:

```prisma
// schema.prisma
model User {
  id            String    @id @default(cuid())
  email         String    @unique
  emailVerified Boolean   @default(false)
  name          String?
  image         String?
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt

  sessions      Session[]
  accounts      Account[]
}

model Session {
  id        String   @id @default(cuid())
  userId    String
  expiresAt DateTime
  token     String   @unique
  ipAddress String?
  userAgent String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([userId])
}

model Account {
  id                String  @id @default(cuid())
  userId            String
  type              String
  provider          String
  providerAccountId String
  refresh_token     String?
  access_token      String?
  expires_at        Int?
  token_type        String?
  scope             String?
  id_token          String?
  session_state     String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([provider, providerAccountId])
  @@index([userId])
}

model Verification {
  id         String   @id @default(cuid())
  identifier String
  value      String
  expiresAt  DateTime

  @@unique([identifier, value])
}
```

Execute as migrações:

```bash
bunx prisma migrate dev --name init
```

### 3. Integrar com Fastify

Configure o servidor Fastify com Better-Auth:

```typescript
// server.ts
import Fastify from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import { auth } from "./lib/auth";

const fastify = Fastify({ logger: true });

// Registrar plugins necessários
await fastify.register(cors, {
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
});

await fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET,
});

// Montar rotas de autenticação do Better-Auth
fastify.all("/api/auth/*", async (request, reply) => {
  return auth.handler(request.raw, reply.raw);
});

await fastify.listen({ port: 3000, host: "0.0.0.0" });
```

### 4. Documentar com OpenAPI/Scalar

Better-Auth pode gerar automaticamente o schema OpenAPI. Integre com Scalar:

```typescript
// server.ts
import Fastify from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import swagger from "@fastify/swagger";
import scalar from "@scalar/fastify-api-reference";
import { auth } from "./lib/auth";

const fastify = Fastify({ logger: true });

// Registrar plugins
await fastify.register(cors, {
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
});

await fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET,
});

// Gerar schema OpenAPI do Better-Auth
const betterAuthSchema = await auth.api.generateOpenAPISchema();

// Configurar Swagger/OpenAPI mesclando com Better-Auth
await fastify.register(swagger, {
  openapi: {
    ...betterAuthSchema,
    info: {
      title: "API with Better-Auth",
      description: "Complete API with Better-Auth authentication",
      version: "1.0.0",
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "Development server",
      },
    ],
  },
});

// Registrar Scalar UI
await fastify.register(scalar, {
  routePrefix: "/docs",
  configuration: {
    theme: "purple",
    darkMode: true,
  },
});

// Montar rotas de autenticação do Better-Auth
fastify.all("/api/auth/*", async (request, reply) => {
  return auth.handler(request.raw, reply.raw);
});

await fastify.listen({ port: 3000, host: "0.0.0.0" });
console.log("🚀 Server running at http://localhost:3000");
console.log("📚 API docs at http://localhost:3000/docs");
```

Para mesclar o schema do Better-Auth com seus endpoints customizados:

```typescript
// lib/merge-openapi.ts
import { OpenAPIV3 } from "openapi-types";

export function mergeOpenAPISchemas(
  betterAuthSchema: OpenAPIV3.Document,
  customSchema: Partial<OpenAPIV3.Document>,
): OpenAPIV3.Document {
  return {
    ...betterAuthSchema,
    info: {
      ...betterAuthSchema.info,
      ...customSchema.info,
    },
    servers: customSchema.servers || betterAuthSchema.servers,
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

// Uso no server.ts
import { mergeOpenAPISchemas } from "./lib/merge-openapi";

const betterAuthSchema = await auth.api.generateOpenAPISchema();

const customSchema: Partial<OpenAPIV3.Document> = {
  info: {
    title: "My API",
    version: "1.0.0",
  },
  tags: [
    { name: "users", description: "User management" },
    { name: "products", description: "Product management" },
  ],
  paths: {
    "/api/users": {
      get: {
        tags: ["users"],
        summary: "List users",
        responses: {
          "200": {
            description: "List of users",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { type: "object" },
                },
              },
            },
          },
        },
      },
    },
  },
};

const mergedSchema = mergeOpenAPISchemas(betterAuthSchema, customSchema);

await fastify.register(swagger, {
  openapi: mergedSchema,
});
```

## Endpoints de Autenticação

Better-Auth cria automaticamente os seguintes endpoints:

```typescript
// Registro
POST /api/auth/sign-up
Body: { email: string, password: string, name?: string }

// Login
POST /api/auth/sign-in
Body: { email: string, password: string }

// Logout
POST /api/auth/sign-out

// Verificar sessão
GET /api/auth/session

// Listar sessões do usuário
GET /api/auth/list-sessions

// Revogar sessão
POST /api/auth/revoke-session
Body: { sessionId: string }

// Esqueci minha senha
POST /api/auth/forgot-password
Body: { email: string }

// Resetar senha
POST /api/auth/reset-password
Body: { token: string, password: string }
```

## Middleware de Autenticação

Crie middlewares para proteger rotas:

```typescript
// middleware/auth.ts
import { FastifyRequest, FastifyReply } from "fastify";
import { auth } from "../lib/auth";

export async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  // Extrair sessão do header ou cookie
  const authHeader = request.headers.authorization;
  const sessionToken =
    authHeader?.replace("Bearer ", "") || request.cookies.session;

  if (!sessionToken) {
    return reply.status(401).send({
      error: "Unauthorized",
      message: "Authentication required",
    });
  }

  // Validar sessão
  const session = await auth.api.getSession({
    headers: request.headers as any,
  });

  if (!session) {
    return reply.status(401).send({
      error: "Unauthorized",
      message: "Invalid or expired session",
    });
  }

  // Adicionar usuário ao request
  request.user = session.user;
  request.session = session.session;
}

// Middleware de autorização por role
export function requireRole(...roles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    await requireAuth(request, reply);

    const userRole = request.user?.role;

    if (!userRole || !roles.includes(userRole)) {
      return reply.status(403).send({
        error: "Forbidden",
        message: "Insufficient permissions",
      });
    }
  };
}

// Type augmentation
declare module "fastify" {
  interface FastifyRequest {
    user?: {
      id: string;
      email: string;
      name?: string;
      role?: string;
    };
    session?: {
      id: string;
      expiresAt: Date;
    };
  }
}
```

## Protegendo Rotas

Use os middlewares para proteger endpoints:

```typescript
// routes/users.ts
import { FastifyPluginAsync } from "fastify";
import { requireAuth, requireRole } from "../middleware/auth";

const usersRoutes: FastifyPluginAsync = async (fastify) => {
  // Rota pública
  fastify.get("/users", async (request, reply) => {
    const users = await getPublicUsers();
    return users;
  });

  // Rota protegida - apenas autenticados
  fastify.get(
    "/users/me",
    {
      preHandler: [requireAuth],
    },
    async (request, reply) => {
      return request.user;
    },
  );

  // Rota protegida - apenas admins
  fastify.delete(
    "/users/:id",
    {
      preHandler: [requireRole("admin")],
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      await deleteUser(id);
      return { message: "User deleted successfully" };
    },
  );

  // Múltiplos roles
  fastify.post(
    "/users/:id/verify",
    {
      preHandler: [requireRole("admin", "moderator")],
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      await verifyUser(id);
      return { message: "User verified" };
    },
  );
};

export default usersRoutes;
```

## Helpers de Autenticação

Crie funções auxiliares para operações comuns:

```typescript
// lib/auth-helpers.ts
import { auth } from "./auth";
import { FastifyRequest } from "fastify";

// Obter usuário atual
export async function getCurrentUser(request: FastifyRequest) {
  const session = await auth.api.getSession({
    headers: request.headers as any,
  });

  return session?.user || null;
}

// Verificar se usuário está autenticado
export async function isAuthenticated(
  request: FastifyRequest,
): Promise<boolean> {
  const user = await getCurrentUser(request);
  return !!user;
}

// Verificar permissão
export async function hasRole(
  request: FastifyRequest,
  ...roles: string[]
): Promise<boolean> {
  const user = await getCurrentUser(request);
  return user?.role ? roles.includes(user.role) : false;
}

// Criar sessão manualmente
export async function createSession(userId: string) {
  return await auth.api.signIn({
    userId,
  });
}

// Invalidar sessão
export async function invalidateSession(sessionId: string) {
  return await auth.api.revokeSession({
    sessionId,
  });
}

// Listar todas as sessões do usuário
export async function getUserSessions(userId: string) {
  return await auth.api.listSessions({
    userId,
  });
}
```

## Variáveis de Ambiente

Configure as variáveis necessárias:

```bash
# .env
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/mydb"

# Better-Auth
BETTER_AUTH_SECRET="your-secret-key-at-least-32-chars"
BETTER_AUTH_URL="http://localhost:3000"

# Cookies
COOKIE_SECRET="your-cookie-secret"

# Frontend (CORS)
FRONTEND_URL="http://localhost:5173"

# Email (para verificação e reset de senha)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER="your-email@gmail.com"
SMTP_PASSWORD="your-app-password"
```

## Validação com Zod

Integre validação de schemas nas rotas de auth:

```typescript
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

const SignUpSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain uppercase letter")
    .regex(/[a-z]/, "Password must contain lowercase letter")
    .regex(/[0-9]/, "Password must contain number"),
  name: z.string().min(2).max(100).optional(),
});

fastify.post<{
  Body: z.infer<typeof SignUpSchema>;
}>(
  "/auth/sign-up",
  {
    schema: {
      body: zodToJsonSchema(SignUpSchema),
    },
  },
  async (request, reply) => {
    const validated = SignUpSchema.parse(request.body);

    // Better-Auth já valida, mas você pode adicionar lógica customizada
    const result = await auth.api.signUp({
      email: validated.email,
      password: validated.password,
      name: validated.name,
    });

    return result;
  },
);
```

## Plugin: Username Authentication

Permite autenticação com username ao invés de (ou junto com) email:

```typescript
// lib/auth.ts
import { betterAuth } from "better-auth";
import { username } from "better-auth/plugins";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),

  plugins: [
    username({
      // Username ou email
      usernameOrEmail: true,

      // Apenas username (sem email)
      // usernameOrEmail: false,
    }),
  ],

  // Configurações padrão
  emailAndPassword: {
    enabled: true,
  },

  secret: process.env.BETTER_AUTH_SECRET!,
  baseURL: process.env.BETTER_AUTH_URL!,
});
```

Schema do banco com username:

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
}
```

Uso nas rotas:

```typescript
// Sign up com username
fastify.post("/auth/sign-up", async (request, reply) => {
  const { username, email, password, name } = request.body;

  const result = await auth.api.signUp({
    username,
    email,
    password,
    name,
  });

  return result;
});

// Sign in com username ou email
fastify.post("/auth/sign-in", async (request, reply) => {
  const { usernameOrEmail, password } = request.body;

  const result = await auth.api.signIn({
    usernameOrEmail, // Aceita username ou email
    password,
  });

  return result;
});
```

## Plugin: Organizations

Permite criar organizações (empresas, times) com membros e roles:

```typescript
// lib/auth.ts
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),

  plugins: [
    organization({
      // Permitir usuários criarem organizações
      allowUserToCreateOrganization: true,

      // Limite de organizações por usuário
      maxOrganizationsPerUser: 5,

      // Roles disponíveis
      roles: ["owner", "admin", "member"],

      // Permissões
      permissions: [
        "organization:read",
        "organization:update",
        "organization:delete",
        "member:invite",
        "member:remove",
        "member:update-role",
      ],
    }),
  ],

  secret: process.env.BETTER_AUTH_SECRET!,
  baseURL: process.env.BETTER_AUTH_URL!,
});
```

Schema do banco com organizations:

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
}

model OrganizationInvite {
  id             String       @id @default(cuid())
  organizationId String
  email          String
  role           String
  invitedBy      String
  expiresAt      DateTime
  status         String       // pending, accepted, expired
  createdAt      DateTime     @default(now())

  organization   Organization @relation(fields: [organizationId], references: [id], onDelete: Cascade)

  @@unique([organizationId, email])
}
```

Endpoints automáticos de organizations:

```typescript
// Criar organização
POST /api/auth/organization/create
Body: { name: string, slug: string }

// Listar organizações do usuário
GET /api/auth/organization/list

// Obter organização
GET /api/auth/organization/:id

// Atualizar organização
PATCH /api/auth/organization/:id
Body: { name?: string, logo?: string }

// Deletar organização
DELETE /api/auth/organization/:id

// Convidar membro
POST /api/auth/organization/:id/invite
Body: { email: string, role: string }

// Listar membros
GET /api/auth/organization/:id/members

// Atualizar role de membro
PATCH /api/auth/organization/:id/members/:userId
Body: { role: string }

// Remover membro
DELETE /api/auth/organization/:id/members/:userId

// Aceitar convite
POST /api/auth/organization/invite/accept
Body: { inviteId: string }
```

Middleware para verificar acesso à organização:

```typescript
// middleware/organization.ts
import { FastifyRequest, FastifyReply } from "fastify";
import { auth } from "../lib/auth";

export function requireOrganizationAccess(
  requiredRole?: "owner" | "admin" | "member",
) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    await requireAuth(request, reply);

    const { organizationId } = request.params as { organizationId: string };

    const member = await auth.api.organization.getMember({
      organizationId,
      userId: request.user!.id,
    });

    if (!member) {
      return reply.status(403).send({
        error: "Access denied",
        message: "You are not a member of this organization",
      });
    }

    if (requiredRole) {
      const roleHierarchy = { owner: 3, admin: 2, member: 1 };
      const userRoleLevel =
        roleHierarchy[member.role as keyof typeof roleHierarchy];
      const requiredLevel = roleHierarchy[requiredRole];

      if (userRoleLevel < requiredLevel) {
        return reply.status(403).send({
          error: "Insufficient permissions",
          message: `This action requires ${requiredRole} role`,
        });
      }
    }

    request.organization = {
      id: organizationId,
      memberRole: member.role,
    };
  };
}

// Type augmentation
declare module "fastify" {
  interface FastifyRequest {
    organization?: {
      id: string;
      memberRole: string;
    };
  }
}
```

## Checklist de Implementação

Ao integrar Fastify com Better-Auth:

- [ ] Instalar dependências: `better-auth`, `@fastify/cors`, `@fastify/cookie`
- [ ] Configurar adapter de banco de dados (Prisma, Drizzle, etc)
- [ ] Criar schema do banco com tabelas User, Session, Account, Verification
- [ ] Executar migrações do banco de dados
- [ ] Configurar Better-Auth com secret e baseURL
- [ ] Registrar plugins CORS e Cookie no Fastify
- [ ] Montar rotas do Better-Auth em `/api/auth/*`
- [ ] Criar middleware `requireAuth` para rotas protegidas
- [ ] Criar middleware `requireRole` para autorização
- [ ] Adicionar type augmentation para FastifyRequest
- [ ] Configurar variáveis de ambiente
- [ ] Testar fluxo de sign-up, sign-in e sign-out
- [ ] Implementar proteção de rotas com preHandler
- [ ] Configurar SMTP para emails (opcional, mas recomendado)

## Recursos Adicionais

Para exemplos completos de implementação, veja [examples.md](examples.md).

Para configurações avançadas e OAuth, veja [reference.md](reference.md).

## Melhores Práticas

1. **Use HTTPS em produção** - Essencial para segurança de cookies
2. **Configure CORS adequadamente** - Apenas origens confiáveis
3. **Habilite verificação de email** - Em produção, sempre requeira verificação
4. **Use secrets fortes** - Mínimo 32 caracteres, gerados aleatoriamente
5. **Implemente rate limiting** - Previna brute force em endpoints de auth
6. **Monitore sessões** - Implemente limpeza de sessões expiradas
7. **Use cookies httpOnly** - Better-Auth já faz isso por padrão
8. **Implemente refresh tokens** - Para sessões de longa duração
9. **Log tentativas de auth** - Para auditoria e segurança
10. **Teste fluxos de erro** - Email já existe, senha incorreta, etc
