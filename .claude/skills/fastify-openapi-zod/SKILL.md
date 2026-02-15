---
name: fastify-openapi-zod
description: Create Fastify APIs with automatic OpenAPI documentation using Zod schemas for validation and type safety. Use when building REST APIs, creating endpoints, setting up API documentation, or when the user mentions Fastify, OpenAPI, Swagger, or Zod validation.
---

# Fastify + OpenAPI + Zod

Crie APIs Fastify com documentação OpenAPI automática e validação de schemas usando Zod.

## Dependências Necessárias

```bash
bun add fastify @fastify/swagger @scalar/fastify-api-reference zod zod-to-json-schema
bun add -D @types/node
```

## Setup Inicial

Configure o Fastify com Swagger/OpenAPI e Scalar:

```typescript
import Fastify from "fastify";
import swagger from "@fastify/swagger";
import scalar from "@scalar/fastify-api-reference";

const fastify = Fastify({
  logger: true,
});

// Registrar plugin Swagger
await fastify.register(swagger, {
  openapi: {
    info: {
      title: "API Documentation",
      description: "API documentation with Fastify",
      version: "1.0.0",
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "Development server",
      },
    ],
    tags: [
      { name: "users", description: "User management endpoints" },
      { name: "products", description: "Product management endpoints" },
    ],
  },
});

// Registrar Scalar (interface moderna para documentação)
await fastify.register(scalar, {
  routePrefix: "/docs",
  configuration: {
    theme: "purple", // Temas: 'purple', 'blue', 'green', 'kepler', 'mars', 'moon', 'solarized'
    darkMode: true,
  },
});

await fastify.listen({ port: 3000, host: "0.0.0.0" });
console.log("API docs available at http://localhost:3000/docs");
```

## Criando Schemas com Zod

Defina schemas Zod e converta-os para JSON Schema:

```typescript
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

// Schema de entrada
const CreateUserSchema = z.object({
  name: z.string().min(3).max(100),
  email: z.string().email(),
  age: z.number().int().min(18).optional(),
  role: z.enum(["admin", "user", "guest"]).default("user"),
});

// Schema de saída
const UserResponseSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  email: z.string().email(),
  age: z.number().int().optional(),
  role: z.string(),
  createdAt: z.string().datetime(),
});

// Schema de erro
const ErrorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
  details: z.record(z.any()).optional(),
});

// Tipos TypeScript derivados dos schemas
type CreateUserInput = z.infer<typeof CreateUserSchema>;
type UserResponse = z.infer<typeof UserResponseSchema>;
type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
```

## Criando Rotas com Schema

### Padrão Básico

```typescript
fastify.post<{
  Body: CreateUserInput;
  Reply: UserResponse | ErrorResponse;
}>(
  "/users",
  {
    schema: {
      description: "Create a new user",
      tags: ["users"],
      body: zodToJsonSchema(CreateUserSchema),
      response: {
        200: zodToJsonSchema(UserResponseSchema),
        400: zodToJsonSchema(ErrorResponseSchema),
      },
    },
  },
  async (request, reply) => {
    // Validação automática via Zod
    const validated = CreateUserSchema.parse(request.body);

    const user = await createUser(validated);
    return reply.status(200).send(user);
  },
);
```

### Rota com Params e Query

```typescript
const GetUserParamsSchema = z.object({
  userId: z.string().uuid(),
});

const GetUsersQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  role: z.enum(["admin", "user", "guest"]).optional(),
});

fastify.get<{
  Params: z.infer<typeof GetUserParamsSchema>;
  Reply: UserResponse | ErrorResponse;
}>(
  "/users/:userId",
  {
    schema: {
      description: "Get user by ID",
      tags: ["users"],
      params: zodToJsonSchema(GetUserParamsSchema),
      response: {
        200: zodToJsonSchema(UserResponseSchema),
        404: zodToJsonSchema(ErrorResponseSchema),
      },
    },
  },
  async (request, reply) => {
    const { userId } = GetUserParamsSchema.parse(request.params);

    const user = await getUser(userId);
    if (!user) {
      return reply.status(404).send({
        error: "User not found",
        message: `User with ID ${userId} does not exist`,
      });
    }

    return user;
  },
);

fastify.get<{
  Querystring: z.infer<typeof GetUsersQuerySchema>;
}>(
  "/users",
  {
    schema: {
      description: "List users with pagination",
      tags: ["users"],
      querystring: zodToJsonSchema(GetUsersQuerySchema),
      response: {
        200: zodToJsonSchema(
          z.object({
            data: z.array(UserResponseSchema),
            pagination: z.object({
              page: z.number(),
              limit: z.number(),
              total: z.number(),
            }),
          }),
        ),
      },
    },
  },
  async (request, reply) => {
    const query = GetUsersQuerySchema.parse(request.query);
    const result = await listUsers(query);
    return result;
  },
);
```

## Validação e Error Handling

### Handler de Erros Global

```typescript
import { ZodError } from "zod";

fastify.setErrorHandler((error, request, reply) => {
  // Erros de validação Zod
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

  // Erros de negócio customizados
  if (error.statusCode === 422) {
    return reply.status(422).send({
      error: "Business logic error",
      message: error.message,
    });
  }

  // Erros inesperados
  request.log.error(error);
  return reply.status(500).send({
    error: "Internal server error",
    message: "An unexpected error occurred",
  });
});
```

### Validação Manual com Zod

```typescript
fastify.post("/orders", async (request, reply) => {
  // Validação com tratamento de erro
  const result = OrderSchema.safeParse(request.body);

  if (!result.success) {
    return reply.status(400).send({
      error: "Invalid order data",
      details: result.error.errors,
    });
  }

  const order = await createOrder(result.data);
  return order;
});
```

## Organizando Rotas em Plugins

### Estrutura de Diretórios

```
src/
├── server.ts          # Setup principal
├── routes/
│   ├── users.ts       # Rotas de usuários
│   ├── products.ts    # Rotas de produtos
│   └── index.ts       # Registro de rotas
└── schemas/
    ├── users.ts       # Schemas de usuários
    ├── products.ts    # Schemas de produtos
    └── common.ts      # Schemas comuns
```

### Plugin de Rotas

```typescript
// routes/users.ts
import { FastifyPluginAsync } from "fastify";
import { CreateUserSchema, UserResponseSchema } from "../schemas/users";
import { zodToJsonSchema } from "zod-to-json-schema";

const usersRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.post<{
    Body: z.infer<typeof CreateUserSchema>;
  }>(
    "/users",
    {
      schema: {
        description: "Create user",
        tags: ["users"],
        body: zodToJsonSchema(CreateUserSchema),
        response: {
          200: zodToJsonSchema(UserResponseSchema),
        },
      },
    },
    async (request, reply) => {
      const validated = CreateUserSchema.parse(request.body);
      const user = await createUser(validated);
      return user;
    },
  );

  // Mais rotas...
};

export default usersRoutes;
```

### Registro de Plugins

```typescript
// routes/index.ts
import { FastifyPluginAsync } from "fastify";
import usersRoutes from "./users";
import productsRoutes from "./products";

const routes: FastifyPluginAsync = async (fastify) => {
  await fastify.register(usersRoutes);
  await fastify.register(productsRoutes);
};

export default routes;

// server.ts
import routes from "./routes";

await fastify.register(routes);
```

## Schemas Reutilizáveis

### Schemas Comuns

```typescript
// schemas/common.ts
import { z } from "zod";

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

export const ErrorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
  details: z.record(z.any()).optional(),
});

export const IdParamSchema = z.object({
  id: z.string().uuid(),
});

// Schema base para timestamps
export const TimestampsSchema = z.object({
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
```

### Composição de Schemas

```typescript
// schemas/users.ts
import { z } from "zod";
import { TimestampsSchema } from "./common";

const UserBaseSchema = z.object({
  name: z.string().min(3).max(100),
  email: z.string().email(),
  age: z.number().int().min(18).optional(),
});

export const CreateUserSchema = UserBaseSchema;

export const UpdateUserSchema = UserBaseSchema.partial();

export const UserResponseSchema = UserBaseSchema.extend({
  id: z.string().uuid(),
  role: z.string(),
}).merge(TimestampsSchema);
```

## Autenticação e Hooks

### Hook de Autenticação

```typescript
import { FastifyRequest, FastifyReply } from "fastify";

async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  const token = request.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return reply.status(401).send({
      error: "Authentication required",
      message: "Please provide a valid token",
    });
  }

  const user = await verifyToken(token);
  if (!user) {
    return reply.status(401).send({
      error: "Invalid token",
      message: "Token is expired or invalid",
    });
  }

  request.user = user;
}

// Usar em rotas específicas
fastify.post(
  "/users",
  {
    preHandler: [authenticate],
    schema: {
      description: "Create user (requires authentication)",
      tags: ["users"],
      security: [{ bearerAuth: [] }],
      body: zodToJsonSchema(CreateUserSchema),
      response: {
        200: zodToJsonSchema(UserResponseSchema),
        401: zodToJsonSchema(ErrorResponseSchema),
      },
    },
  },
  async (request, reply) => {
    const user = await createUser(request.body);
    return user;
  },
);
```

### Configurar Security no OpenAPI

```typescript
await fastify.register(swagger, {
  openapi: {
    info: {
      title: "API Documentation",
      version: "1.0.0",
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
});
```

## Checklist de Implementação

Ao criar uma API Fastify com OpenAPI + Zod:

- [ ] Instalar dependências: `fastify`, `@fastify/swagger`, `@scalar/fastify-api-reference`, `zod`, `zod-to-json-schema`
- [ ] Configurar Swagger/OpenAPI com informações da API (título, versão, tags)
- [ ] Registrar Scalar para interface de documentação
- [ ] Definir schemas Zod para inputs e outputs
- [ ] Converter schemas Zod para JSON Schema com `zodToJsonSchema`
- [ ] Adicionar schemas no objeto `schema` das rotas
- [ ] Implementar error handler global para ZodError
- [ ] Organizar schemas em arquivos separados (`schemas/`)
- [ ] Organizar rotas em plugins (`routes/`)
- [ ] Adicionar documentação de segurança se usar autenticação
- [ ] Testar a documentação em `/docs`
- [ ] Validar que os códigos de status HTTP estão corretos (200, 400, 404, 422, 500)

## Recursos Adicionais

Para exemplos completos de implementação, veja [examples.md](examples.md).

Para referência de configurações e plugins, veja [reference.md](reference.md).

## Melhores Práticas

1. **Sempre defina schemas Zod primeiro** - Derive os tipos TypeScript dos schemas
2. **Use `.safeParse()` para validações complexas** - Permite tratamento de erro customizado
3. **Reutilize schemas comuns** - Evite duplicação de código
4. **Organize por domínio** - Agrupe schemas e rotas relacionadas
5. **Documente com `description` e `tags`** - Melhora a documentação OpenAPI
6. **Use enums do Zod** - Garante valores válidos e documenta opções
7. **Defina responses para todos os status codes** - Melhora a documentação
8. **Use `coerce` para query params** - Query strings sempre vêm como strings
