# Exemplos Completos - Fastify + OpenAPI + Zod

## Exemplo 1: API CRUD Completa de Usuários

### Estrutura de Arquivos

```
src/
├── server.ts
├── routes/
│   └── users.ts
├── schemas/
│   ├── common.ts
│   └── users.ts
└── services/
    └── users.ts
```

### schemas/common.ts

```typescript
import { z } from "zod";

export const ErrorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
  details: z.any().optional(),
});

export const PaginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

export const PaginationResponseSchema = z.object({
  page: z.number(),
  limit: z.number(),
  total: z.number(),
  totalPages: z.number(),
});

export const IdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
export type PaginationQuery = z.infer<typeof PaginationQuerySchema>;
export type PaginationResponse = z.infer<typeof PaginationResponseSchema>;
export type IdParam = z.infer<typeof IdParamSchema>;
```

### schemas/users.ts

```typescript
import { z } from "zod";

// Schema base
const UserBaseSchema = z.object({
  name: z.string().min(3, "Name must be at least 3 characters").max(100),
  email: z.string().email("Invalid email format"),
  age: z.number().int().min(18, "Must be at least 18 years old").optional(),
  role: z.enum(["admin", "user", "guest"]).default("user"),
});

// Schema para criação (todos os campos obrigatórios exceto age)
export const CreateUserSchema = UserBaseSchema;

// Schema para atualização (todos os campos opcionais)
export const UpdateUserSchema = UserBaseSchema.partial().refine(
  (data) => Object.keys(data).length > 0,
  { message: "At least one field must be provided" },
);

// Schema de resposta (inclui campos do sistema)
export const UserResponseSchema = UserBaseSchema.extend({
  id: z.string().uuid(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

// Schema para listagem com filtros
export const ListUsersQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  role: z.enum(["admin", "user", "guest"]).optional(),
  search: z.string().optional(),
});

// Tipos TypeScript
export type CreateUser = z.infer<typeof CreateUserSchema>;
export type UpdateUser = z.infer<typeof UpdateUserSchema>;
export type UserResponse = z.infer<typeof UserResponseSchema>;
export type ListUsersQuery = z.infer<typeof ListUsersQuerySchema>;
```

### routes/users.ts

```typescript
import { FastifyPluginAsync } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  CreateUserSchema,
  UpdateUserSchema,
  UserResponseSchema,
  ListUsersQuerySchema,
  CreateUser,
  UpdateUser,
  ListUsersQuery,
} from "../schemas/users";
import {
  ErrorResponseSchema,
  IdParamSchema,
  PaginationResponseSchema,
  IdParam,
} from "../schemas/common";
import * as userService from "../services/users";

const usersRoutes: FastifyPluginAsync = async (fastify) => {
  // CREATE - POST /users
  fastify.post<{
    Body: CreateUser;
    Reply: UserResponse;
  }>(
    "/users",
    {
      schema: {
        description: "Create a new user",
        tags: ["users"],
        body: zodToJsonSchema(CreateUserSchema, { $refStrategy: "none" }),
        response: {
          200: zodToJsonSchema(UserResponseSchema, { $refStrategy: "none" }),
          400: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
          422: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
        },
      },
    },
    async (request, reply) => {
      const validated = CreateUserSchema.parse(request.body);

      // Verifica se email já existe
      const existingUser = await userService.findByEmail(validated.email);
      if (existingUser) {
        return reply.status(422).send({
          error: "User already exists",
          message: `User with email ${validated.email} already exists`,
        });
      }

      const user = await userService.create(validated);
      return reply.status(200).send(user);
    },
  );

  // LIST - GET /users
  fastify.get<{
    Querystring: ListUsersQuery;
  }>(
    "/users",
    {
      schema: {
        description: "List users with pagination and filters",
        tags: ["users"],
        querystring: zodToJsonSchema(ListUsersQuerySchema, {
          $refStrategy: "none",
        }),
        response: {
          200: zodToJsonSchema(
            z.object({
              data: z.array(UserResponseSchema),
              pagination: PaginationResponseSchema,
            }),
            { $refStrategy: "none" },
          ),
        },
      },
    },
    async (request, reply) => {
      const query = ListUsersQuerySchema.parse(request.query);
      const result = await userService.list(query);
      return result;
    },
  );

  // GET BY ID - GET /users/:id
  fastify.get<{
    Params: IdParam;
    Reply: UserResponse;
  }>(
    "/users/:id",
    {
      schema: {
        description: "Get user by ID",
        tags: ["users"],
        params: zodToJsonSchema(IdParamSchema, { $refStrategy: "none" }),
        response: {
          200: zodToJsonSchema(UserResponseSchema, { $refStrategy: "none" }),
          404: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
        },
      },
    },
    async (request, reply) => {
      const { id } = IdParamSchema.parse(request.params);

      const user = await userService.findById(id);
      if (!user) {
        return reply.status(404).send({
          error: "User not found",
          message: `User with ID ${id} does not exist`,
        });
      }

      return user;
    },
  );

  // UPDATE - PUT /users/:id
  fastify.put<{
    Params: IdParam;
    Body: UpdateUser;
    Reply: UserResponse;
  }>(
    "/users/:id",
    {
      schema: {
        description: "Update user by ID",
        tags: ["users"],
        params: zodToJsonSchema(IdParamSchema, { $refStrategy: "none" }),
        body: zodToJsonSchema(UpdateUserSchema, { $refStrategy: "none" }),
        response: {
          200: zodToJsonSchema(UserResponseSchema, { $refStrategy: "none" }),
          400: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
          404: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
        },
      },
    },
    async (request, reply) => {
      const { id } = IdParamSchema.parse(request.params);
      const validated = UpdateUserSchema.parse(request.body);

      const user = await userService.findById(id);
      if (!user) {
        return reply.status(404).send({
          error: "User not found",
          message: `User with ID ${id} does not exist`,
        });
      }

      const updated = await userService.update(id, validated);
      return updated;
    },
  );

  // DELETE - DELETE /users/:id
  fastify.delete<{
    Params: IdParam;
  }>(
    "/users/:id",
    {
      schema: {
        description: "Delete user by ID",
        tags: ["users"],
        params: zodToJsonSchema(IdParamSchema, { $refStrategy: "none" }),
        response: {
          200: zodToJsonSchema(z.object({ message: z.string() }), {
            $refStrategy: "none",
          }),
          404: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
        },
      },
    },
    async (request, reply) => {
      const { id } = IdParamSchema.parse(request.params);

      const user = await userService.findById(id);
      if (!user) {
        return reply.status(404).send({
          error: "User not found",
          message: `User with ID ${id} does not exist`,
        });
      }

      await userService.remove(id);
      return { message: "User deleted successfully" };
    },
  );
};

export default usersRoutes;
```

### server.ts

```typescript
import Fastify from "fastify";
import swagger from "@fastify/swagger";
import scalar from "@scalar/fastify-api-reference";
import { ZodError } from "zod";
import usersRoutes from "./routes/users";

const fastify = Fastify({
  logger: {
    level: "info",
    transport: {
      target: "pino-pretty",
      options: {
        translateTime: "HH:MM:ss Z",
        ignore: "pid,hostname",
      },
    },
  },
});

// Registrar Swagger
await fastify.register(swagger, {
  openapi: {
    info: {
      title: "User Management API",
      description: "API for managing users with full CRUD operations",
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
    ],
    tags: [
      {
        name: "users",
        description: "User management endpoints",
      },
    ],
  },
});

// Registrar Scalar
await fastify.register(scalar, {
  routePrefix: "/docs",
  configuration: {
    theme: "purple",
    darkMode: true,
  },
});

// Error handler global
fastify.setErrorHandler((error, request, reply) => {
  if (error instanceof ZodError) {
    return reply.status(400).send({
      error: "Validation error",
      message: "Invalid request data",
      details: error.errors.map((e) => ({
        field: e.path.join("."),
        message: e.message,
        code: e.code,
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
await fastify.register(usersRoutes);

// Iniciar servidor
try {
  await fastify.listen({ port: 3000, host: "0.0.0.0" });
  console.log("🚀 Server running at http://localhost:3000");
  console.log("📚 API docs at http://localhost:3000/docs");
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
```

## Exemplo 2: API com Autenticação JWT

### schemas/auth.ts

```typescript
import { z } from "zod";

export const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const RegisterSchema = z.object({
  name: z.string().min(3).max(100),
  email: z.string().email(),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number"),
});

export const TokenResponseSchema = z.object({
  accessToken: z.string(),
  tokenType: z.literal("Bearer"),
  expiresIn: z.number(),
});

export type LoginInput = z.infer<typeof LoginSchema>;
export type RegisterInput = z.infer<typeof RegisterSchema>;
export type TokenResponse = z.infer<typeof TokenResponseSchema>;
```

### routes/auth.ts

```typescript
import { FastifyPluginAsync } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  LoginSchema,
  RegisterSchema,
  TokenResponseSchema,
  LoginInput,
  RegisterInput,
} from "../schemas/auth";
import { ErrorResponseSchema } from "../schemas/common";
import { UserResponseSchema } from "../schemas/users";
import * as authService from "../services/auth";

const authRoutes: FastifyPluginAsync = async (fastify) => {
  // POST /auth/register
  fastify.post<{
    Body: RegisterInput;
  }>(
    "/auth/register",
    {
      schema: {
        description: "Register a new user account",
        tags: ["auth"],
        body: zodToJsonSchema(RegisterSchema, { $refStrategy: "none" }),
        response: {
          200: zodToJsonSchema(TokenResponseSchema, { $refStrategy: "none" }),
          400: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
          422: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
        },
      },
    },
    async (request, reply) => {
      const validated = RegisterSchema.parse(request.body);

      const existing = await authService.findByEmail(validated.email);
      if (existing) {
        return reply.status(422).send({
          error: "Email already registered",
          message: "An account with this email already exists",
        });
      }

      const token = await authService.register(validated);
      return token;
    },
  );

  // POST /auth/login
  fastify.post<{
    Body: LoginInput;
  }>(
    "/auth/login",
    {
      schema: {
        description: "Login with email and password",
        tags: ["auth"],
        body: zodToJsonSchema(LoginSchema, { $refStrategy: "none" }),
        response: {
          200: zodToJsonSchema(TokenResponseSchema, { $refStrategy: "none" }),
          401: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
        },
      },
    },
    async (request, reply) => {
      const validated = LoginSchema.parse(request.body);

      const token = await authService.login(validated);
      if (!token) {
        return reply.status(401).send({
          error: "Invalid credentials",
          message: "Email or password is incorrect",
        });
      }

      return token;
    },
  );

  // GET /auth/me (requer autenticação)
  fastify.get(
    "/auth/me",
    {
      preHandler: [fastify.authenticate], // Hook de autenticação
      schema: {
        description: "Get current user profile",
        tags: ["auth"],
        security: [{ bearerAuth: [] }],
        response: {
          200: zodToJsonSchema(UserResponseSchema, { $refStrategy: "none" }),
          401: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
        },
      },
    },
    async (request, reply) => {
      return request.user;
    },
  );
};

export default authRoutes;
```

### decorators/auth.ts (Hook de autenticação)

```typescript
import { FastifyRequest, FastifyReply } from "fastify";
import jwt from "jsonwebtoken";

declare module "fastify" {
  interface FastifyInstance {
    authenticate: (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => Promise<void>;
  }
  interface FastifyRequest {
    user?: any;
  }
}

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  try {
    const authHeader = request.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return reply.status(401).send({
        error: "Authentication required",
        message: "Please provide a valid Bearer token",
      });
    }

    const token = authHeader.replace("Bearer ", "");
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);

    request.user = decoded;
  } catch (error) {
    return reply.status(401).send({
      error: "Invalid token",
      message: "Token is expired or invalid",
    });
  }
}
```

### server.ts (com autenticação)

```typescript
import Fastify from "fastify";
import swagger from "@fastify/swagger";
import scalar from "@scalar/fastify-api-reference";
import { authenticate } from "./decorators/auth";
import authRoutes from "./routes/auth";
import usersRoutes from "./routes/users";

const fastify = Fastify({ logger: true });

// Registrar decorator de autenticação
fastify.decorate("authenticate", authenticate);

// Configurar Swagger com segurança
await fastify.register(swagger, {
  openapi: {
    info: {
      title: "Authenticated API",
      version: "1.0.0",
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "Enter your JWT token",
        },
      },
    },
  },
});

await fastify.register(scalar, {
  routePrefix: "/docs",
  configuration: {
    theme: "purple",
    darkMode: true,
  },
});

// Registrar rotas
await fastify.register(authRoutes);
await fastify.register(usersRoutes);

await fastify.listen({ port: 3000, host: "0.0.0.0" });
```

## Exemplo 3: Validação Complexa com Refinements

```typescript
import { z } from "zod";

// Schema com validações customizadas
export const CreateOrderSchema = z
  .object({
    userId: z.string().uuid(),
    items: z
      .array(
        z.object({
          productId: z.string().uuid(),
          quantity: z.number().int().min(1).max(100),
        }),
      )
      .min(1, "Order must have at least one item"),
    shippingAddress: z.object({
      street: z.string().min(5),
      city: z.string().min(2),
      state: z.string().length(2),
      zipCode: z.string().regex(/^\d{5}(-\d{4})?$/, "Invalid ZIP code format"),
    }),
    couponCode: z.string().optional(),
    totalAmount: z.number().positive(),
  })
  .refine(
    async (data) => {
      // Validação assíncrona - verifica se o cupom é válido
      if (data.couponCode) {
        const isValid = await validateCoupon(data.couponCode);
        return isValid;
      }
      return true;
    },
    { message: "Invalid or expired coupon code" },
  )
  .refine(
    (data) => {
      // Validação de lógica de negócio - total deve ser positivo
      return data.totalAmount > 0;
    },
    { message: "Total amount must be greater than zero" },
  );

// Uso na rota
fastify.post<{
  Body: z.infer<typeof CreateOrderSchema>;
}>(
  "/orders",
  {
    schema: {
      description: "Create a new order",
      tags: ["orders"],
      body: zodToJsonSchema(CreateOrderSchema, { $refStrategy: "none" }),
      response: {
        200: zodToJsonSchema(OrderResponseSchema, { $refStrategy: "none" }),
        400: zodToJsonSchema(ErrorResponseSchema, { $refStrategy: "none" }),
      },
    },
  },
  async (request, reply) => {
    // safeParse para tratamento de erro customizado
    const result = await CreateOrderSchema.safeParseAsync(request.body);

    if (!result.success) {
      return reply.status(400).send({
        error: "Validation failed",
        message: "Order data is invalid",
        details: result.error.errors,
      });
    }

    const order = await createOrder(result.data);
    return order;
  },
);
```

## Exemplo 4: Upload de Arquivos

```typescript
import multipart from "@fastify/multipart";
import { z } from "zod";

// Registrar plugin multipart
await fastify.register(multipart, {
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
});

// Schema para metadata do upload
const UploadMetadataSchema = z.object({
  title: z.string().min(3).max(100),
  description: z.string().max(500).optional(),
});

fastify.post(
  "/upload",
  {
    schema: {
      description: "Upload a file with metadata",
      tags: ["files"],
      consumes: ["multipart/form-data"],
      response: {
        200: zodToJsonSchema(
          z.object({
            fileId: z.string(),
            filename: z.string(),
            size: z.number(),
            url: z.string(),
          }),
          { $refStrategy: "none" },
        ),
      },
    },
  },
  async (request, reply) => {
    const data = await request.file();

    if (!data) {
      return reply.status(400).send({
        error: "No file provided",
        message: "Please upload a file",
      });
    }

    // Validar metadata
    const metadata = UploadMetadataSchema.parse({
      title: data.fields.title?.value,
      description: data.fields.description?.value,
    });

    // Processar arquivo
    const buffer = await data.toBuffer();
    const fileId = await saveFile(buffer, data.filename, metadata);

    return {
      fileId,
      filename: data.filename,
      size: buffer.length,
      url: `/files/${fileId}`,
    };
  },
);
```
