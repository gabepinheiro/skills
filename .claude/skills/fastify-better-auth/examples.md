# Exemplos Completos - Fastify + Better-Auth

## Exemplo 1: Setup Completo com Email/Password

### Estrutura de Arquivos

```
src/
├── server.ts
├── lib/
│   ├── auth.ts
│   ├── auth-helpers.ts
│   └── prisma.ts
├── middleware/
│   └── auth.ts
├── routes/
│   ├── auth.ts
│   └── users.ts
└── schemas/
    └── auth.ts
```

### lib/prisma.ts

```typescript
import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === "development"
        ? ["query", "error", "warn"]
        : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
```

### lib/auth.ts

```typescript
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { prisma } from "./prisma";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: process.env.NODE_ENV === "production",
    minPasswordLength: 8,
    maxPasswordLength: 128,
  },

  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 dias
    updateAge: 60 * 60 * 24, // Atualiza a cada 24h
    cookieCache: {
      enabled: true,
      maxAge: 60 * 5, // 5 minutos
    },
  },

  user: {
    additionalFields: {
      role: {
        type: "string",
        defaultValue: "user",
        required: false,
      },
    },
  },

  advanced: {
    cookiePrefix: "better-auth",
    crossSubDomainCookies: {
      enabled: false,
    },
  },

  secret: process.env.BETTER_AUTH_SECRET!,
  baseURL: process.env.BETTER_AUTH_URL || "http://localhost:3000",

  trustedOrigins: [process.env.FRONTEND_URL || "http://localhost:5173"],
});

export type Session = typeof auth.$Infer.Session.session;
export type User = typeof auth.$Infer.Session.user;
```

### middleware/auth.ts

```typescript
import { FastifyRequest, FastifyReply } from "fastify";
import { auth } from "../lib/auth";

declare module "fastify" {
  interface FastifyRequest {
    user?: {
      id: string;
      email: string;
      name?: string;
      role?: string;
      emailVerified: boolean;
    };
    session?: {
      id: string;
      expiresAt: Date;
      userId: string;
    };
  }
}

export async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  try {
    const session = await auth.api.getSession({
      headers: request.headers as any,
    });

    if (!session?.user) {
      return reply.status(401).send({
        error: "Unauthorized",
        message: "Authentication required",
      });
    }

    request.user = session.user;
    request.session = session.session;
  } catch (error) {
    request.log.error(error, "Authentication error");
    return reply.status(401).send({
      error: "Unauthorized",
      message: "Invalid or expired session",
    });
  }
}

export function requireRole(...allowedRoles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    await requireAuth(request, reply);

    const userRole = request.user?.role || "user";

    if (!allowedRoles.includes(userRole)) {
      return reply.status(403).send({
        error: "Forbidden",
        message: `This action requires one of these roles: ${allowedRoles.join(", ")}`,
        requiredRoles: allowedRoles,
        userRole,
      });
    }
  };
}

export async function requireEmailVerified(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  await requireAuth(request, reply);

  if (!request.user?.emailVerified) {
    return reply.status(403).send({
      error: "Email not verified",
      message: "Please verify your email before accessing this resource",
    });
  }
}
```

### schemas/auth.ts

```typescript
import { z } from "zod";

export const SignUpSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password is too long")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(
      /[^A-Za-z0-9]/,
      "Password must contain at least one special character",
    ),
  name: z.string().min(2).max(100).optional(),
});

export const SignInSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(1, "Password is required"),
  rememberMe: z.boolean().optional(),
});

export const UpdatePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain uppercase letter")
    .regex(/[a-z]/, "Password must contain lowercase letter")
    .regex(/[0-9]/, "Password must contain number"),
});

export const ForgotPasswordSchema = z.object({
  email: z.string().email("Invalid email format"),
});

export const ResetPasswordSchema = z.object({
  token: z.string().min(1, "Token is required"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain uppercase letter")
    .regex(/[a-z]/, "Password must contain lowercase letter")
    .regex(/[0-9]/, "Password must contain number"),
});

export type SignUpInput = z.infer<typeof SignUpSchema>;
export type SignInInput = z.infer<typeof SignInSchema>;
export type UpdatePasswordInput = z.infer<typeof UpdatePasswordSchema>;
export type ForgotPasswordInput = z.infer<typeof ForgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof ResetPasswordSchema>;
```

### routes/auth.ts

```typescript
import { FastifyPluginAsync } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { auth } from "../lib/auth";
import { requireAuth } from "../middleware/auth";
import {
  SignUpSchema,
  SignInSchema,
  UpdatePasswordSchema,
  ForgotPasswordSchema,
  ResetPasswordSchema,
} from "../schemas/auth";

const authRoutes: FastifyPluginAsync = async (fastify) => {
  // Better-Auth handler - gerencia todos os endpoints de auth
  fastify.all("/auth/*", async (request, reply) => {
    return auth.handler(request.raw, reply.raw);
  });

  // Endpoint customizado: Sign up com validação Zod
  fastify.post<{
    Body: z.infer<typeof SignUpSchema>;
  }>(
    "/auth/sign-up",
    {
      schema: {
        description: "Register a new user account",
        tags: ["auth"],
        body: zodToJsonSchema(SignUpSchema, { $refStrategy: "none" }),
        response: {
          200: {
            type: "object",
            properties: {
              user: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  email: { type: "string" },
                  name: { type: "string" },
                },
              },
              session: {
                type: "object",
                properties: {
                  token: { type: "string" },
                  expiresAt: { type: "string" },
                },
              },
            },
          },
          400: {
            type: "object",
            properties: {
              error: { type: "string" },
              message: { type: "string" },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const validated = SignUpSchema.parse(request.body);

      try {
        const result = await auth.api.signUp({
          email: validated.email,
          password: validated.password,
          name: validated.name,
        });

        return result;
      } catch (error: any) {
        request.log.error(error, "Sign up error");

        if (error.message?.includes("already exists")) {
          return reply.status(400).send({
            error: "Email already registered",
            message: "An account with this email already exists",
          });
        }

        throw error;
      }
    },
  );

  // Endpoint customizado: Sign in com validação
  fastify.post<{
    Body: z.infer<typeof SignInSchema>;
  }>(
    "/auth/sign-in",
    {
      schema: {
        description: "Sign in with email and password",
        tags: ["auth"],
        body: zodToJsonSchema(SignInSchema, { $refStrategy: "none" }),
      },
    },
    async (request, reply) => {
      const validated = SignInSchema.parse(request.body);

      try {
        const result = await auth.api.signIn({
          email: validated.email,
          password: validated.password,
        });

        return result;
      } catch (error: any) {
        request.log.error(error, "Sign in error");

        return reply.status(401).send({
          error: "Invalid credentials",
          message: "Email or password is incorrect",
        });
      }
    },
  );

  // Obter usuário atual
  fastify.get(
    "/auth/me",
    {
      preHandler: [requireAuth],
      schema: {
        description: "Get current user",
        tags: ["auth"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      return request.user;
    },
  );

  // Listar sessões do usuário
  fastify.get(
    "/auth/sessions",
    {
      preHandler: [requireAuth],
      schema: {
        description: "List all user sessions",
        tags: ["auth"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      const sessions = await auth.api.listSessions({
        userId: request.user!.id,
      });

      return sessions;
    },
  );

  // Revogar sessão específica
  fastify.post<{
    Body: { sessionId: string };
  }>(
    "/auth/revoke-session",
    {
      preHandler: [requireAuth],
      schema: {
        description: "Revoke a specific session",
        tags: ["auth"],
        security: [{ bearerAuth: [] }],
        body: {
          type: "object",
          required: ["sessionId"],
          properties: {
            sessionId: { type: "string" },
          },
        },
      },
    },
    async (request, reply) => {
      const { sessionId } = request.body;

      await auth.api.revokeSession({
        sessionId,
      });

      return { message: "Session revoked successfully" };
    },
  );

  // Atualizar senha
  fastify.post<{
    Body: z.infer<typeof UpdatePasswordSchema>;
  }>(
    "/auth/update-password",
    {
      preHandler: [requireAuth],
      schema: {
        description: "Update user password",
        tags: ["auth"],
        security: [{ bearerAuth: [] }],
        body: zodToJsonSchema(UpdatePasswordSchema, { $refStrategy: "none" }),
      },
    },
    async (request, reply) => {
      const validated = UpdatePasswordSchema.parse(request.body);

      try {
        await auth.api.changePassword({
          userId: request.user!.id,
          currentPassword: validated.currentPassword,
          newPassword: validated.newPassword,
        });

        return { message: "Password updated successfully" };
      } catch (error: any) {
        if (error.message?.includes("incorrect")) {
          return reply.status(400).send({
            error: "Invalid password",
            message: "Current password is incorrect",
          });
        }

        throw error;
      }
    },
  );
};

export default authRoutes;
```

### routes/users.ts

```typescript
import { FastifyPluginAsync } from "fastify";
import {
  requireAuth,
  requireRole,
  requireEmailVerified,
} from "../middleware/auth";

const usersRoutes: FastifyPluginAsync = async (fastify) => {
  // Rota pública
  fastify.get(
    "/users",
    {
      schema: {
        description: "List public users",
        tags: ["users"],
      },
    },
    async (request, reply) => {
      const users = await prisma.user.findMany({
        select: {
          id: true,
          name: true,
          image: true,
          // Não expor email em rotas públicas
        },
        take: 50,
      });

      return users;
    },
  );

  // Obter perfil próprio (requer autenticação)
  fastify.get(
    "/users/me",
    {
      preHandler: [requireAuth],
      schema: {
        description: "Get current user profile",
        tags: ["users"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      const user = await prisma.user.findUnique({
        where: { id: request.user!.id },
        include: {
          sessions: {
            select: {
              id: true,
              createdAt: true,
              expiresAt: true,
              ipAddress: true,
              userAgent: true,
            },
          },
        },
      });

      return user;
    },
  );

  // Atualizar perfil próprio
  fastify.patch<{
    Body: { name?: string; image?: string };
  }>(
    "/users/me",
    {
      preHandler: [requireAuth],
      schema: {
        description: "Update current user profile",
        tags: ["users"],
        security: [{ bearerAuth: [] }],
        body: {
          type: "object",
          properties: {
            name: { type: "string", minLength: 2, maxLength: 100 },
            image: { type: "string", format: "uri" },
          },
        },
      },
    },
    async (request, reply) => {
      const { name, image } = request.body;

      const updated = await prisma.user.update({
        where: { id: request.user!.id },
        data: {
          ...(name && { name }),
          ...(image && { image }),
          updatedAt: new Date(),
        },
      });

      return updated;
    },
  );

  // Deletar conta própria (requer email verificado)
  fastify.delete(
    "/users/me",
    {
      preHandler: [requireAuth, requireEmailVerified],
      schema: {
        description: "Delete current user account",
        tags: ["users"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      await prisma.user.delete({
        where: { id: request.user!.id },
      });

      return { message: "Account deleted successfully" };
    },
  );

  // Admin: Listar todos os usuários
  fastify.get(
    "/admin/users",
    {
      preHandler: [requireRole("admin")],
      schema: {
        description: "List all users (admin only)",
        tags: ["admin"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      const users = await prisma.user.findMany({
        include: {
          _count: {
            select: {
              sessions: true,
            },
          },
        },
      });

      return users;
    },
  );

  // Admin: Atualizar role de usuário
  fastify.patch<{
    Params: { userId: string };
    Body: { role: string };
  }>(
    "/admin/users/:userId/role",
    {
      preHandler: [requireRole("admin")],
      schema: {
        description: "Update user role (admin only)",
        tags: ["admin"],
        security: [{ bearerAuth: [] }],
        params: {
          type: "object",
          properties: {
            userId: { type: "string" },
          },
        },
        body: {
          type: "object",
          required: ["role"],
          properties: {
            role: { type: "string", enum: ["user", "admin", "moderator"] },
          },
        },
      },
    },
    async (request, reply) => {
      const { userId } = request.params;
      const { role } = request.body;

      const updated = await prisma.user.update({
        where: { id: userId },
        data: { role },
      });

      return updated;
    },
  );
};

export default usersRoutes;
```

### server.ts

```typescript
import Fastify from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import swagger from "@fastify/swagger";
import scalar from "@scalar/fastify-api-reference";
import { ZodError } from "zod";

import authRoutes from "./routes/auth";
import usersRoutes from "./routes/users";

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || "info",
    transport:
      process.env.NODE_ENV === "development"
        ? {
            target: "pino-pretty",
            options: {
              translateTime: "HH:MM:ss Z",
              ignore: "pid,hostname",
            },
          }
        : undefined,
  },
});

// CORS
await fastify.register(cors, {
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
});

// Cookies
await fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET,
  hook: "onRequest",
  parseOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
});

// Swagger
await fastify.register(swagger, {
  openapi: {
    info: {
      title: "API with Authentication",
      description: "API with Better-Auth integration",
      version: "1.0.0",
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "Development",
      },
    ],
    tags: [
      { name: "auth", description: "Authentication endpoints" },
      { name: "users", description: "User management" },
      { name: "admin", description: "Admin operations" },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "Session Token",
        },
      },
    },
  },
});

// Scalar
await fastify.register(scalar, {
  routePrefix: "/docs",
  configuration: {
    theme: "purple",
    darkMode: true,
  },
});

// Error handler
fastify.setErrorHandler((error, request, reply) => {
  if (error instanceof ZodError) {
    return reply.status(400).send({
      error: "Validation error",
      message: "Invalid request data",
      details: error.errors.map((e) => ({
        field: e.path.join("."),
        message: e.message,
      })),
    });
  }

  request.log.error(error);

  return reply.status(error.statusCode || 500).send({
    error: error.name || "Internal Server Error",
    message: error.message || "An unexpected error occurred",
  });
});

// Registrar rotas
await fastify.register(authRoutes, { prefix: "/api" });
await fastify.register(usersRoutes, { prefix: "/api" });

// Health check
fastify.get("/health", async () => {
  return { status: "ok", timestamp: new Date().toISOString() };
});

// Iniciar servidor
try {
  await fastify.listen({
    port: parseInt(process.env.PORT || "3000"),
    host: "0.0.0.0",
  });

  console.log("🚀 Server running at http://localhost:3000");
  console.log("📚 API docs at http://localhost:3000/docs");
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
```

## Exemplo 2: Cliente TypeScript

Para consumir a API do frontend:

```typescript
// lib/auth-client.ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  credentials: "include",
});

// Usar no frontend
async function handleSignUp(email: string, password: string, name?: string) {
  try {
    const result = await authClient.signUp({
      email,
      password,
      name,
    });

    console.log("Signed up:", result);
  } catch (error) {
    console.error("Sign up error:", error);
  }
}

async function handleSignIn(email: string, password: string) {
  try {
    const result = await authClient.signIn({
      email,
      password,
    });

    console.log("Signed in:", result);
  } catch (error) {
    console.error("Sign in error:", error);
  }
}

async function handleSignOut() {
  await authClient.signOut();
}

async function getCurrentUser() {
  const session = await authClient.getSession();
  return session?.user;
}
```

## Exemplo 3: Rate Limiting em Rotas de Auth

```typescript
import rateLimit from "@fastify/rate-limit";

await fastify.register(rateLimit, {
  global: false,
});

// Aplicar rate limit em rotas de autenticação
fastify.post(
  "/auth/sign-in",
  {
    config: {
      rateLimit: {
        max: 5, // 5 tentativas
        timeWindow: "15 minutes",
        errorResponseBuilder: () => ({
          error: "Too many attempts",
          message: "Please try again later",
        }),
      },
    },
  },
  async (request, reply) => {
    // handler
  },
);

fastify.post(
  "/auth/sign-up",
  {
    config: {
      rateLimit: {
        max: 3, // 3 registros
        timeWindow: "1 hour",
      },
    },
  },
  async (request, reply) => {
    // handler
  },
);
```

## Exemplo 4: Autenticação com Username

### lib/auth.ts

```typescript
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { username } from "better-auth/plugins";
import { prisma } from "./prisma";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),

  // Plugin username
  plugins: [
    username({
      usernameOrEmail: true, // Aceita username OU email no login
    }),
  ],

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
  },

  session: {
    expiresIn: 60 * 60 * 24 * 7,
  },

  secret: process.env.BETTER_AUTH_SECRET!,
  baseURL: process.env.BETTER_AUTH_URL!,
});
```

### schemas/auth.ts

```typescript
import { z } from "zod";

export const SignUpWithUsernameSchema = z.object({
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(20, "Username is too long")
    .regex(
      /^[a-zA-Z0-9_]+$/,
      "Username can only contain letters, numbers, and underscores",
    )
    .regex(/^[a-zA-Z]/, "Username must start with a letter"),
  email: z.string().email("Invalid email format"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain uppercase letter")
    .regex(/[a-z]/, "Password must contain lowercase letter")
    .regex(/[0-9]/, "Password must contain number"),
  name: z.string().min(2).max(100).optional(),
});

export const SignInWithUsernameSchema = z.object({
  usernameOrEmail: z.string().min(1, "Username or email is required"),
  password: z.string().min(1, "Password is required"),
});

export type SignUpWithUsernameInput = z.infer<typeof SignUpWithUsernameSchema>;
export type SignInWithUsernameInput = z.infer<typeof SignInWithUsernameSchema>;
```

### routes/auth.ts

```typescript
import { FastifyPluginAsync } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { auth } from "../lib/auth";
import {
  SignUpWithUsernameSchema,
  SignInWithUsernameSchema,
} from "../schemas/auth";

const authRoutes: FastifyPluginAsync = async (fastify) => {
  // Better-Auth handler
  fastify.all("/auth/*", async (request, reply) => {
    return auth.handler(request.raw, reply.raw);
  });

  // Sign up com username
  fastify.post<{
    Body: z.infer<typeof SignUpWithUsernameSchema>;
  }>(
    "/auth/sign-up",
    {
      schema: {
        description: "Register with username",
        tags: ["auth"],
        body: zodToJsonSchema(SignUpWithUsernameSchema, {
          $refStrategy: "none",
        }),
      },
    },
    async (request, reply) => {
      const validated = SignUpWithUsernameSchema.parse(request.body);

      try {
        // Verificar se username já existe
        const existingUser = await prisma.user.findUnique({
          where: { username: validated.username },
        });

        if (existingUser) {
          return reply.status(400).send({
            error: "Username taken",
            message: "This username is already in use",
          });
        }

        const result = await auth.api.signUp({
          username: validated.username,
          email: validated.email,
          password: validated.password,
          name: validated.name,
        });

        return result;
      } catch (error: any) {
        request.log.error(error, "Sign up error");

        if (
          error.message?.includes("email") &&
          error.message?.includes("exists")
        ) {
          return reply.status(400).send({
            error: "Email already registered",
            message: "An account with this email already exists",
          });
        }

        throw error;
      }
    },
  );

  // Sign in com username ou email
  fastify.post<{
    Body: z.infer<typeof SignInWithUsernameSchema>;
  }>(
    "/auth/sign-in",
    {
      schema: {
        description: "Sign in with username or email",
        tags: ["auth"],
        body: zodToJsonSchema(SignInWithUsernameSchema, {
          $refStrategy: "none",
        }),
      },
    },
    async (request, reply) => {
      const validated = SignInWithUsernameSchema.parse(request.body);

      try {
        const result = await auth.api.signIn({
          usernameOrEmail: validated.usernameOrEmail,
          password: validated.password,
        });

        return result;
      } catch (error: any) {
        request.log.error(error, "Sign in error");

        return reply.status(401).send({
          error: "Invalid credentials",
          message: "Username/email or password is incorrect",
        });
      }
    },
  );

  // Verificar disponibilidade do username
  fastify.get<{
    Querystring: { username: string };
  }>(
    "/auth/check-username",
    {
      schema: {
        description: "Check if username is available",
        tags: ["auth"],
        querystring: {
          type: "object",
          required: ["username"],
          properties: {
            username: { type: "string" },
          },
        },
      },
    },
    async (request, reply) => {
      const { username } = request.query;

      const existing = await prisma.user.findUnique({
        where: { username },
        select: { id: true },
      });

      return {
        available: !existing,
        username,
      };
    },
  );
};

export default authRoutes;
```

## Exemplo 5: Organizations (Multi-tenancy)

### lib/auth.ts

```typescript
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { organization } from "better-auth/plugins";
import { prisma } from "./prisma";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "postgresql",
  }),

  plugins: [
    organization({
      allowUserToCreateOrganization: true,
      maxOrganizationsPerUser: 5,

      roles: ["owner", "admin", "member"],

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

      // Role permissions mapping
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
    }),
  ],

  emailAndPassword: {
    enabled: true,
  },

  secret: process.env.BETTER_AUTH_SECRET!,
  baseURL: process.env.BETTER_AUTH_URL!,
});
```

### middleware/organization.ts

```typescript
import { FastifyRequest, FastifyReply } from "fastify";
import { auth } from "../lib/auth";
import { requireAuth } from "./auth";

declare module "fastify" {
  interface FastifyRequest {
    organization?: {
      id: string;
      slug: string;
      memberRole: string;
      hasPermission: (permission: string) => boolean;
    };
  }
}

export function requireOrganization(
  options: {
    role?: "owner" | "admin" | "member";
    permission?: string;
  } = {},
) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    await requireAuth(request, reply);

    const { organizationId } = request.params as { organizationId?: string };

    if (!organizationId) {
      return reply.status(400).send({
        error: "Missing organization",
        message: "Organization ID is required",
      });
    }

    // Buscar organização e membro
    const [organization, member] = await Promise.all([
      prisma.organization.findUnique({
        where: { id: organizationId },
      }),
      prisma.organizationMember.findUnique({
        where: {
          organizationId_userId: {
            organizationId,
            userId: request.user!.id,
          },
        },
      }),
    ]);

    if (!organization) {
      return reply.status(404).send({
        error: "Organization not found",
        message: "The organization does not exist",
      });
    }

    if (!member) {
      return reply.status(403).send({
        error: "Access denied",
        message: "You are not a member of this organization",
      });
    }

    // Verificar role mínima
    if (options.role) {
      const roleHierarchy = { owner: 3, admin: 2, member: 1 };
      const userLevel =
        roleHierarchy[member.role as keyof typeof roleHierarchy];
      const requiredLevel = roleHierarchy[options.role];

      if (userLevel < requiredLevel) {
        return reply.status(403).send({
          error: "Insufficient permissions",
          message: `This action requires ${options.role} role`,
          userRole: member.role,
          requiredRole: options.role,
        });
      }
    }

    // Verificar permissão específica
    if (options.permission) {
      const hasPermission = await auth.api.organization.hasPermission({
        organizationId,
        userId: request.user!.id,
        permission: options.permission,
      });

      if (!hasPermission) {
        return reply.status(403).send({
          error: "Permission denied",
          message: `You don't have the required permission: ${options.permission}`,
        });
      }
    }

    // Adicionar dados da organização ao request
    request.organization = {
      id: organization.id,
      slug: organization.slug,
      memberRole: member.role,
      hasPermission: async (permission: string) => {
        return await auth.api.organization.hasPermission({
          organizationId: organization.id,
          userId: request.user!.id,
          permission,
        });
      },
    };
  };
}
```

### schemas/organization.ts

```typescript
import { z } from "zod";

export const CreateOrganizationSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters").max(100),
  slug: z
    .string()
    .min(3, "Slug must be at least 3 characters")
    .max(50)
    .regex(
      /^[a-z0-9-]+$/,
      "Slug can only contain lowercase letters, numbers, and hyphens",
    )
    .regex(/^[a-z]/, "Slug must start with a letter"),
  logo: z.string().url().optional(),
  metadata: z.record(z.any()).optional(),
});

export const UpdateOrganizationSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  slug: z
    .string()
    .min(3)
    .max(50)
    .regex(/^[a-z0-9-]+$/)
    .optional(),
  logo: z.string().url().optional(),
  metadata: z.record(z.any()).optional(),
});

export const InviteMemberSchema = z.object({
  email: z.string().email(),
  role: z.enum(["owner", "admin", "member"]),
});

export const UpdateMemberRoleSchema = z.object({
  role: z.enum(["owner", "admin", "member"]),
});

export type CreateOrganizationInput = z.infer<typeof CreateOrganizationSchema>;
export type UpdateOrganizationInput = z.infer<typeof UpdateOrganizationSchema>;
export type InviteMemberInput = z.infer<typeof InviteMemberSchema>;
export type UpdateMemberRoleInput = z.infer<typeof UpdateMemberRoleSchema>;
```

### routes/organizations.ts

```typescript
import { FastifyPluginAsync } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import { requireAuth } from "../middleware/auth";
import { requireOrganization } from "../middleware/organization";
import {
  CreateOrganizationSchema,
  UpdateOrganizationSchema,
  InviteMemberSchema,
  UpdateMemberRoleSchema,
} from "../schemas/organization";
import { auth } from "../lib/auth";

const organizationsRoutes: FastifyPluginAsync = async (fastify) => {
  // Better-Auth handlers para organizations
  fastify.all("/organizations/*", async (request, reply) => {
    return auth.handler(request.raw, reply.raw);
  });

  // Criar organização
  fastify.post<{
    Body: z.infer<typeof CreateOrganizationSchema>;
  }>(
    "/organizations",
    {
      preHandler: [requireAuth],
      schema: {
        description: "Create a new organization",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
        body: zodToJsonSchema(CreateOrganizationSchema, {
          $refStrategy: "none",
        }),
      },
    },
    async (request, reply) => {
      const validated = CreateOrganizationSchema.parse(request.body);

      // Verificar se slug está disponível
      const existing = await prisma.organization.findUnique({
        where: { slug: validated.slug },
      });

      if (existing) {
        return reply.status(400).send({
          error: "Slug taken",
          message: "This organization slug is already in use",
        });
      }

      const organization = await auth.api.organization.create({
        userId: request.user!.id,
        name: validated.name,
        slug: validated.slug,
        logo: validated.logo,
        metadata: validated.metadata,
      });

      return organization;
    },
  );

  // Listar organizações do usuário
  fastify.get(
    "/organizations",
    {
      preHandler: [requireAuth],
      schema: {
        description: "List user organizations",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      const organizations = await auth.api.organization.list({
        userId: request.user!.id,
      });

      return organizations;
    },
  );

  // Obter organização específica
  fastify.get<{
    Params: { organizationId: string };
  }>(
    "/organizations/:organizationId",
    {
      preHandler: [requireOrganization()],
      schema: {
        description: "Get organization details",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      const organization = await prisma.organization.findUnique({
        where: { id: request.organization!.id },
        include: {
          _count: {
            select: {
              members: true,
            },
          },
        },
      });

      return {
        ...organization,
        userRole: request.organization!.memberRole,
      };
    },
  );

  // Atualizar organização
  fastify.patch<{
    Params: { organizationId: string };
    Body: z.infer<typeof UpdateOrganizationSchema>;
  }>(
    "/organizations/:organizationId",
    {
      preHandler: [requireOrganization({ role: "admin" })],
      schema: {
        description: "Update organization (admin+)",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
        body: zodToJsonSchema(UpdateOrganizationSchema, {
          $refStrategy: "none",
        }),
      },
    },
    async (request, reply) => {
      const validated = UpdateOrganizationSchema.parse(request.body);

      // Se mudar slug, verificar disponibilidade
      if (validated.slug) {
        const existing = await prisma.organization.findFirst({
          where: {
            slug: validated.slug,
            NOT: { id: request.organization!.id },
          },
        });

        if (existing) {
          return reply.status(400).send({
            error: "Slug taken",
            message: "This organization slug is already in use",
          });
        }
      }

      const updated = await prisma.organization.update({
        where: { id: request.organization!.id },
        data: validated,
      });

      return updated;
    },
  );

  // Deletar organização
  fastify.delete<{
    Params: { organizationId: string };
  }>(
    "/organizations/:organizationId",
    {
      preHandler: [requireOrganization({ role: "owner" })],
      schema: {
        description: "Delete organization (owner only)",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      await prisma.organization.delete({
        where: { id: request.organization!.id },
      });

      return { message: "Organization deleted successfully" };
    },
  );

  // Listar membros
  fastify.get<{
    Params: { organizationId: string };
  }>(
    "/organizations/:organizationId/members",
    {
      preHandler: [requireOrganization()],
      schema: {
        description: "List organization members",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      const members = await prisma.organizationMember.findMany({
        where: { organizationId: request.organization!.id },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              image: true,
            },
          },
        },
        orderBy: [
          { role: "desc" }, // Owners primeiro
          { createdAt: "asc" },
        ],
      });

      return members;
    },
  );

  // Convidar membro
  fastify.post<{
    Params: { organizationId: string };
    Body: z.infer<typeof InviteMemberSchema>;
  }>(
    "/organizations/:organizationId/invite",
    {
      preHandler: [requireOrganization({ permission: "member:invite" })],
      schema: {
        description: "Invite member to organization",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
        body: zodToJsonSchema(InviteMemberSchema, { $refStrategy: "none" }),
      },
    },
    async (request, reply) => {
      const validated = InviteMemberSchema.parse(request.body);

      const invite = await auth.api.organization.invite({
        organizationId: request.organization!.id,
        email: validated.email,
        role: validated.role,
        invitedBy: request.user!.id,
      });

      // Enviar email de convite
      // await sendInviteEmail(validated.email, invite);

      return invite;
    },
  );

  // Atualizar role de membro
  fastify.patch<{
    Params: { organizationId: string; memberId: string };
    Body: z.infer<typeof UpdateMemberRoleSchema>;
  }>(
    "/organizations/:organizationId/members/:memberId",
    {
      preHandler: [requireOrganization({ permission: "member:update-role" })],
      schema: {
        description: "Update member role",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
        body: zodToJsonSchema(UpdateMemberRoleSchema, { $refStrategy: "none" }),
      },
    },
    async (request, reply) => {
      const { memberId } = request.params;
      const validated = UpdateMemberRoleSchema.parse(request.body);

      const updated = await auth.api.organization.updateMemberRole({
        organizationId: request.organization!.id,
        userId: memberId,
        role: validated.role,
      });

      return updated;
    },
  );

  // Remover membro
  fastify.delete<{
    Params: { organizationId: string; memberId: string };
  }>(
    "/organizations/:organizationId/members/:memberId",
    {
      preHandler: [requireOrganization({ permission: "member:remove" })],
      schema: {
        description: "Remove member from organization",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      const { memberId } = request.params;

      // Não permitir remover o último owner
      if (request.organization!.memberRole === "owner") {
        const ownerCount = await prisma.organizationMember.count({
          where: {
            organizationId: request.organization!.id,
            role: "owner",
          },
        });

        if (ownerCount === 1) {
          return reply.status(400).send({
            error: "Cannot remove last owner",
            message: "Organization must have at least one owner",
          });
        }
      }

      await auth.api.organization.removeMember({
        organizationId: request.organization!.id,
        userId: memberId,
      });

      return { message: "Member removed successfully" };
    },
  );

  // Sair da organização
  fastify.post<{
    Params: { organizationId: string };
  }>(
    "/organizations/:organizationId/leave",
    {
      preHandler: [requireOrganization()],
      schema: {
        description: "Leave organization",
        tags: ["organizations"],
        security: [{ bearerAuth: [] }],
      },
    },
    async (request, reply) => {
      // Verificar se é o último owner
      if (request.organization!.memberRole === "owner") {
        const ownerCount = await prisma.organizationMember.count({
          where: {
            organizationId: request.organization!.id,
            role: "owner",
          },
        });

        if (ownerCount === 1) {
          return reply.status(400).send({
            error: "Cannot leave",
            message: "Transfer ownership before leaving the organization",
          });
        }
      }

      await auth.api.organization.removeMember({
        organizationId: request.organization!.id,
        userId: request.user!.id,
      });

      return { message: "Left organization successfully" };
    },
  );
};

export default organizationsRoutes;
```

### Uso no server.ts

```typescript
import organizationsRoutes from "./routes/organizations";

// Registrar rotas
await fastify.register(authRoutes, { prefix: "/api" });
await fastify.register(usersRoutes, { prefix: "/api" });
await fastify.register(organizationsRoutes, { prefix: "/api" });
```

## Exemplo 6: OpenAPI/Scalar com Better-Auth

Setup usando `auth.api.generateOpenAPISchema()` para documentação automática.

### lib/merge-openapi.ts

Helper para mesclar o schema do Better-Auth com endpoints customizados:

```typescript
import { OpenAPIV3 } from "openapi-types";

export function mergeOpenAPISchemas(
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
      responses: {
        ...betterAuthSchema.components?.responses,
        ...customSchema.components?.responses,
      },
      parameters: {
        ...betterAuthSchema.components?.parameters,
        ...customSchema.components?.parameters,
      },
    },
    tags: [...(betterAuthSchema.tags || []), ...(customSchema.tags || [])],
  };
}
```

### server.ts

```typescript
import Fastify from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import swagger from "@fastify/swagger";
import scalar from "@scalar/fastify-api-reference";
import { ZodError } from "zod";
import { auth } from "./lib/auth";
import { mergeOpenAPISchemas } from "./lib/merge-openapi";
import usersRoutes from "./routes/users";

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || "info",
  },
});

// CORS
await fastify.register(cors, {
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
});

// Cookies
await fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET,
});

// Gerar schema OpenAPI do Better-Auth automaticamente
const betterAuthSchema = await auth.api.generateOpenAPISchema();

// Mesclar com endpoints customizados
const customSchema = {
  info: {
    title: "My API with Better-Auth",
    description: "Complete API documentation with authentication",
    version: "1.0.0",
    contact: {
      name: "API Support",
      email: "support@example.com",
    },
  },
  servers: [
    {
      url: "http://localhost:3000",
      description: "Development server",
    },
    {
      url: "https://api.example.com",
      description: "Production server",
    },
  ],
  tags: [
    {
      name: "users",
      description: "User management operations",
    },
    {
      name: "products",
      description: "Product management operations",
    },
  ],
};

const mergedSchema = mergeOpenAPISchemas(betterAuthSchema, customSchema);

// Registrar Swagger
await fastify.register(swagger, {
  openapi: mergedSchema,
});

// Registrar Scalar UI
await fastify.register(scalar, {
  routePrefix: "/docs",
  configuration: {
    theme: "purple",
    darkMode: true,
    layout: "modern",
    showSidebar: true,
    metaData: {
      title: "API Documentation",
      description: "Complete API reference with Better-Auth",
    },
  },
});

// Error handler
fastify.setErrorHandler((error, request, reply) => {
  if (error instanceof ZodError) {
    return reply.status(400).send({
      error: "Validation error",
      message: "Invalid request data",
      details: error.errors,
    });
  }

  request.log.error(error);

  return reply.status(error.statusCode || 500).send({
    error: error.name || "Internal Server Error",
    message: error.message,
  });
});

// Montar rotas Better-Auth
fastify.all("/api/auth/*", async (request, reply) => {
  return auth.handler(request.raw, reply.raw);
});

// Registrar outras rotas
await fastify.register(usersRoutes, { prefix: "/api" });

// Health check
fastify.get(
  "/health",
  {
    schema: {
      description: "Health check endpoint",
      tags: ["system"],
      response: {
        200: {
          type: "object",
          properties: {
            status: { type: "string" },
            timestamp: { type: "string" },
          },
        },
      },
    },
  },
  async () => {
    return {
      status: "ok",
      timestamp: new Date().toISOString(),
    };
  },
);

// Iniciar servidor
await fastify.listen({
  port: parseInt(process.env.PORT || "3000"),
  host: "0.0.0.0",
});

console.log("🚀 Server: http://localhost:3000");
console.log("📚 API Docs: http://localhost:3000/docs");
console.log("🔐 Auth: /api/auth/*");
```

### Benefícios dessa Abordagem

1. **Automático**: Better-Auth gera toda a documentação dos endpoints
2. **Sempre atualizado**: Schemas refletem plugins e configuração
3. **Sem duplicação**: Não precisa documentar manualmente
4. **Extensível**: Fácil mesclar com seus endpoints customizados
5. **Type-safe**: Schema gerado corresponde à implementação

### Testando

1. **Acesse a documentação**:

   ```
   http://localhost:3000/docs
   ```

2. **Endpoints Better-Auth documentados automaticamente**:
   - `/api/auth/sign-up` - Registro
   - `/api/auth/sign-in` - Login
   - `/api/auth/sign-out` - Logout
   - `/api/auth/session` - Sessão atual
   - `/api/auth/list-sessions` - Listar sessões
   - E todos os outros endpoints dos plugins instalados

3. **Testar autenticação**:
   - Faça sign-up via Scalar UI
   - Copie o session token da resposta
   - Use o botão "Authorize" para adicionar o token
   - Teste endpoints protegidos

4. **Exportar spec**:

   ```bash
   # JSON
   curl http://localhost:3000/documentation/json > openapi.json

   # Importar em Postman, Insomnia, Bruno, etc
   ```

### Adicionando Endpoints Customizados

Para adicionar seus próprios endpoints ao schema:

```typescript
const customPaths = {
  "/api/users": {
    get: {
      tags: ["users"],
      summary: "List users",
      description: "Get list of all users",
      security: [{ bearerAuth: [] }],
      parameters: [
        {
          name: "page",
          in: "query",
          schema: { type: "integer", minimum: 1, default: 1 },
        },
        {
          name: "limit",
          in: "query",
          schema: { type: "integer", minimum: 1, maximum: 100, default: 20 },
        },
      ],
      responses: {
        "200": {
          description: "Successful response",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  data: {
                    type: "array",
                    items: { $ref: "#/components/schemas/User" },
                  },
                  pagination: {
                    type: "object",
                    properties: {
                      page: { type: "integer" },
                      limit: { type: "integer" },
                      total: { type: "integer" },
                    },
                  },
                },
              },
            },
          },
        },
        "401": {
          description: "Unauthorized",
        },
      },
    },
  },
};

const customSchema = {
  // ... info, servers, tags
  paths: customPaths,
  components: {
    schemas: {
      User: {
        type: "object",
        properties: {
          id: { type: "string" },
          email: { type: "string" },
          name: { type: "string" },
        },
      },
    },
  },
};

const mergedSchema = mergeOpenAPISchemas(betterAuthSchema, customSchema);
```
