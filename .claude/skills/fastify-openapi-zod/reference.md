# Referência - Fastify + OpenAPI + Zod

## Plugins Essenciais

### Core Plugins

```bash
# Framework
bun add fastify

# OpenAPI/Swagger
bun add @fastify/swagger @scalar/fastify-api-reference

# Validação
bun add zod zod-to-json-schema

# CORS
bun add @fastify/cors

# Rate Limiting
bun add @fastify/rate-limit

# Helmet (Security headers)
bun add @fastify/helmet

# JWT
bun add @fastify/jwt

# Multipart (File uploads)
bun add @fastify/multipart

# Static files
bun add @fastify/static

# Cookies
bun add @fastify/cookie
```

## Configurações Avançadas do Swagger

### Customização Completa

```typescript
await fastify.register(swagger, {
  openapi: {
    info: {
      title: "API Documentation",
      description: "Complete API documentation",
      version: "1.0.0",
      termsOfService: "https://example.com/terms",
      contact: {
        name: "API Support",
        url: "https://example.com/support",
        email: "support@example.com",
      },
      license: {
        name: "MIT",
        url: "https://opensource.org/licenses/MIT",
      },
    },
    externalDocs: {
      url: "https://docs.example.com",
      description: "Additional documentation",
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "Development server",
      },
      {
        url: "https://staging.example.com",
        description: "Staging server",
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
        externalDocs: {
          description: "User guide",
          url: "https://docs.example.com/users",
        },
      },
      {
        name: "auth",
        description: "Authentication and authorization",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "JWT Authorization header using the Bearer scheme",
        },
        apiKey: {
          type: "apiKey",
          name: "X-API-Key",
          in: "header",
          description: "API key for server-to-server authentication",
        },
      },
    },
    security: [{ bearerAuth: [] }],
  },
});
```

## Scalar - Interface Moderna para OpenAPI

Scalar é uma alternativa moderna ao Swagger UI, oferecendo:

- **Interface elegante e responsiva** - Design moderno e intuitivo
- **Temas customizáveis** - Múltiplos temas prontos e suporte a CSS customizado
- **Modo escuro nativo** - Suporte completo a dark mode
- **Performance superior** - Carregamento mais rápido que Swagger UI
- **Integração perfeita** - Funciona com qualquer especificação OpenAPI 3.x
- **Client de teste integrado** - Testar APIs diretamente na documentação
- **Geração de código** - Exemplos em múltiplas linguagens automaticamente

### Scalar Customization

```typescript
await fastify.register(scalar, {
  routePrefix: "/docs",
  configuration: {
    // Tema da interface
    theme: "purple", // 'purple', 'blue', 'green', 'red', 'orange', 'default', 'moon', 'solarized'

    // Modo escuro
    darkMode: true,

    // Layout
    layout: "modern", // 'modern', 'classic'

    // Mostrar sidebar
    showSidebar: true,

    // Customizar metadata
    metaData: {
      title: "API Documentation",
      description: "Complete API reference",
      ogDescription: "API documentation for developers",
      ogTitle: "API Docs",
      ogImage: "https://example.com/og-image.png",
      twitterCard: "summary_large_image",
    },

    // Customizar cores
    customCss: `
      .scalar-api-client {
        --scalar-color-1: #121212;
        --scalar-color-2: #1e1e1e;
        --scalar-color-3: #2d2d2d;
        --scalar-color-accent: #8b5cf6;
      }
    `,

    // Ocultar seções
    hiddenClients: false,
    hideModels: false,
    hideDownloadButton: false,

    // Servidor padrão
    defaultHttpClient: {
      targetKey: "javascript", // 'javascript', 'node', 'curl', etc.
      clientKey: "fetch", // 'fetch', 'axios', etc.
    },

    // Autenticação
    authentication: {
      preferredSecurityScheme: "bearerAuth",
      apiKey: {
        token: "", // Token pré-preenchido
      },
    },

    // Servers customizados
    servers: [
      {
        url: "http://localhost:3000",
        description: "Development",
      },
      {
        url: "https://api.example.com",
        description: "Production",
      },
    ],
  },

  // Hooks do Fastify para a rota /docs
  hooks: {
    onRequest: async (request, reply) => {
      // Adicionar autenticação à página de docs
    },
    preHandler: async (request, reply) => {
      // Verificar permissões
    },
  },
});
```

## Zod Schema Patterns

### Tipos Primitivos

```typescript
import { z } from "zod";

// String
const stringSchema = z.string();
const emailSchema = z.string().email();
const urlSchema = z.string().url();
const uuidSchema = z.string().uuid();
const datetimeSchema = z.string().datetime();
const minMaxSchema = z.string().min(3).max(100);
const regexSchema = z.string().regex(/^[A-Z]/);

// Number
const numberSchema = z.number();
const intSchema = z.number().int();
const positiveSchema = z.number().positive();
const rangeSchema = z.number().min(0).max(100);
const multipleSchema = z.number().multipleOf(5);

// Boolean
const boolSchema = z.boolean();

// Date
const dateSchema = z.date();
const minDateSchema = z.date().min(new Date("2020-01-01"));

// Enum
const roleSchema = z.enum(["admin", "user", "guest"]);
const statusSchema = z.nativeEnum(UserStatus); // Enum do TypeScript
```

### Tipos Complexos

```typescript
// Array
const arraySchema = z.array(z.string());
const minMaxArraySchema = z.array(z.string()).min(1).max(10);
const nonEmptySchema = z.array(z.string()).nonempty();

// Object
const objectSchema = z.object({
  name: z.string(),
  age: z.number(),
});

// Record (objeto com chaves dinâmicas)
const recordSchema = z.record(z.string(), z.number());

// Map
const mapSchema = z.map(z.string(), z.number());

// Set
const setSchema = z.set(z.string());

// Tuple
const tupleSchema = z.tuple([z.string(), z.number(), z.boolean()]);

// Union
const unionSchema = z.union([z.string(), z.number()]);
const stringOrNumberSchema = z.string().or(z.number());

// Discriminated Union
const shapeSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("circle"), radius: z.number() }),
  z.object({ type: z.literal("square"), side: z.number() }),
]);

// Intersection
const baseSchema = z.object({ id: z.string() });
const extendedSchema = baseSchema.and(z.object({ name: z.string() }));

// Literal
const literalSchema = z.literal("hello");

// Nullable / Optional
const nullableSchema = z.string().nullable();
const optionalSchema = z.string().optional();
const nullishSchema = z.string().nullish(); // null ou undefined
```

### Transformações e Coerções

```typescript
// Transform
const trimSchema = z.string().transform((val) => val.trim());
const upperSchema = z.string().transform((val) => val.toUpperCase());
const parseIntSchema = z.string().transform((val) => parseInt(val, 10));

// Coerce (útil para query params)
const coerceNumberSchema = z.coerce.number();
const coerceDateSchema = z.coerce.date();
const coerceBooleanSchema = z.coerce.boolean();

// Exemplo: query string sempre vem como string
const QuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  active: z.coerce.boolean().optional(),
});

// URL: /users?page=2&limit=50&active=true
// Resultado: { page: 2, limit: 50, active: true }
```

### Validações Customizadas

```typescript
// Refine - validação customizada
const passwordSchema = z
  .string()
  .min(8)
  .refine((val) => /[A-Z]/.test(val), {
    message: "Password must contain at least one uppercase letter",
  })
  .refine((val) => /[a-z]/.test(val), {
    message: "Password must contain at least one lowercase letter",
  })
  .refine((val) => /[0-9]/.test(val), {
    message: "Password must contain at least one number",
  });

// SuperRefine - múltiplas validações
const schema = z
  .object({
    password: z.string(),
    confirmPassword: z.string(),
  })
  .superRefine((data, ctx) => {
    if (data.password !== data.confirmPassword) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Passwords do not match",
        path: ["confirmPassword"],
      });
    }
  });

// Validação assíncrona
const emailSchema = z
  .string()
  .email()
  .refine(
    async (email) => {
      const exists = await checkEmailExists(email);
      return !exists;
    },
    { message: "Email already registered" },
  );
```

### Composição de Schemas

```typescript
// Extend - adicionar campos
const BaseSchema = z.object({
  id: z.string(),
  name: z.string(),
});

const ExtendedSchema = BaseSchema.extend({
  email: z.string().email(),
  age: z.number(),
});

// Merge - combinar schemas
const TimestampsSchema = z.object({
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

const UserSchema = BaseSchema.merge(TimestampsSchema);

// Pick - selecionar campos
const NameOnlySchema = BaseSchema.pick({ name: true });

// Omit - excluir campos
const WithoutIdSchema = BaseSchema.omit({ id: true });

// Partial - tornar todos os campos opcionais
const PartialSchema = BaseSchema.partial();

// Partial específico - tornar campos específicos opcionais
const PartialNameSchema = BaseSchema.partial({ name: true });

// Required - tornar todos os campos obrigatórios
const RequiredSchema = PartialSchema.required();

// DeepPartial - partial recursivo
const DeepPartialSchema = BaseSchema.deepPartial();
```

## Configuração de Opções do zod-to-json-schema

```typescript
import { zodToJsonSchema } from "zod-to-json-schema";

// Opções disponíveis
const jsonSchema = zodToJsonSchema(MySchema, {
  // Estratégia de referências
  $refStrategy: "none", // 'root', 'relative', 'seen', 'none'

  // Nome base para referências
  name: "MySchema",

  // Namespace para referências
  nameStrategy: "ref", // 'ref', 'title'

  // Target JSON Schema version
  target: "openApi3", // 'jsonSchema7', 'openApi3', 'jsonSchema2019-09'

  // Incluir $schema
  $schema: true,

  // Definições customizadas
  definitions: {},

  // Remover propriedades adicionais
  strictUnions: false,

  // Descrições customizadas
  markdownDescription: false,
});
```

## Fastify Hooks Lifecycle

### Order de Execução

```
onRequest
  ↓
preParsing
  ↓
preValidation
  ↓
preHandler
  ↓
handler (rota)
  ↓
preSerialization
  ↓
onSend
  ↓
onResponse
```

### Exemplos de Hooks

```typescript
// Hook global - executa em todas as rotas
fastify.addHook("onRequest", async (request, reply) => {
  request.log.info({ url: request.url }, "Incoming request");
});

// Hook em rota específica
fastify.get(
  "/users",
  {
    onRequest: async (request, reply) => {
      // Executa antes de processar
    },
    preValidation: async (request, reply) => {
      // Executa antes da validação do schema
    },
    preHandler: async (request, reply) => {
      // Executa antes do handler (comum para auth)
    },
    preSerialization: async (request, reply, payload) => {
      // Modifica o payload antes de serializar
      return { ...payload, timestamp: Date.now() };
    },
  },
  async (request, reply) => {
    return { users: [] };
  },
);

// Hook de erro
fastify.addHook("onError", async (request, reply, error) => {
  request.log.error(error);
});

// Hook onResponse (após enviar resposta)
fastify.addHook("onResponse", async (request, reply) => {
  const responseTime = reply.getResponseTime();
  request.log.info({ responseTime }, "Request completed");
});
```

## Decorators e Plugins Customizados

### Criar Decorator

```typescript
// Adicionar método customizado ao fastify instance
fastify.decorate("utility", function () {
  return "utility value";
});

// Adicionar ao request
fastify.decorateRequest("user", null);

// Adicionar ao reply
fastify.decorateReply("sendSuccess", function (data: any) {
  return this.send({ success: true, data });
});

// Usar TypeScript declarations
declare module "fastify" {
  interface FastifyInstance {
    utility: () => string;
  }
  interface FastifyRequest {
    user: User | null;
  }
  interface FastifyReply {
    sendSuccess: (data: any) => FastifyReply;
  }
}
```

### Criar Plugin

```typescript
import { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";

const myPlugin: FastifyPluginAsync<{ prefix: string }> = async (
  fastify,
  options,
) => {
  // Registrar decorator
  fastify.decorate("config", {
    prefix: options.prefix,
  });

  // Adicionar hook
  fastify.addHook("onRequest", async (request, reply) => {
    request.log.info("Plugin hook");
  });

  // Registrar rotas
  fastify.get(`${options.prefix}/health`, async () => {
    return { status: "ok" };
  });
};

// Exportar com fastify-plugin para tornar global
export default fp(myPlugin, {
  fastify: "4.x",
  name: "my-plugin",
});

// Uso
await fastify.register(myPlugin, { prefix: "/api" });
```

## CORS Configuration

```typescript
import cors from "@fastify/cors";

await fastify.register(cors, {
  origin: true, // Permitir todas as origens (desenvolvimento)
  // origin: 'https://example.com', // Origem específica
  // origin: ['https://example.com', 'https://app.example.com'], // Múltiplas origens
  // origin: (origin, callback) => {
  //   // Lógica customizada
  //   if (!origin || allowedOrigins.includes(origin)) {
  //     callback(null, true);
  //   } else {
  //     callback(new Error('Not allowed by CORS'), false);
  //   }
  // },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["X-Total-Count"],
  maxAge: 86400, // 24 horas
});
```

## Rate Limiting

```typescript
import rateLimit from "@fastify/rate-limit";

await fastify.register(rateLimit, {
  global: true, // Aplicar a todas as rotas
  max: 100, // Máximo de requisições
  timeWindow: "1 minute", // Janela de tempo
  cache: 10000, // Tamanho do cache
  allowList: ["127.0.0.1"], // IPs permitidos
  redis: redisClient, // Usar Redis para storage distribuído
  keyGenerator: (request) => {
    // Gerar chave customizada (ex: por usuário)
    return request.user?.id || request.ip;
  },
  errorResponseBuilder: (request, context) => {
    return {
      error: "Too many requests",
      message: `Rate limit exceeded, retry in ${context.after}`,
      retryAfter: context.after,
    };
  },
  onExceeded: (request, key) => {
    request.log.warn({ key }, "Rate limit exceeded");
  },
});

// Rate limit em rota específica
fastify.get(
  "/expensive",
  {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: "1 minute",
      },
    },
  },
  async (request, reply) => {
    return { data: "expensive operation" };
  },
);
```

## Helmet (Security Headers)

```typescript
import helmet from "@fastify/helmet";

await fastify.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true,
});
```

## Environment Variables e Configuração

```typescript
import { z } from "zod";

// Schema para variáveis de ambiente
const EnvSchema = z.object({
  NODE_ENV: z
    .enum(["development", "production", "test"])
    .default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().default("0.0.0.0"),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace"])
    .default("info"),
});

// Validar ao iniciar a aplicação
const env = EnvSchema.parse(process.env);

// Usar nas configurações
const fastify = Fastify({
  logger: {
    level: env.LOG_LEVEL,
  },
});

await fastify.listen({
  port: env.PORT,
  host: env.HOST,
});
```

## Testing com Fastify

```typescript
import { test } from "node:test";
import { strictEqual } from "node:assert";
import Fastify from "fastify";

test("GET /users returns list of users", async (t) => {
  const app = Fastify();

  app.get("/users", async () => {
    return [{ id: "1", name: "John" }];
  });

  const response = await app.inject({
    method: "GET",
    url: "/users",
  });

  strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  strictEqual(body.length, 1);
  strictEqual(body[0].name, "John");

  await app.close();
});
```

## Performance Tips

1. **Use schema sempre** - A validação de schema é mais rápida que validação manual
2. **Evite `await` desnecessário** - Retorne Promises diretamente quando possível
3. **Use `reply.send()` com cuidado** - Prefer `return` para melhor performance
4. **Configure logger apropriadamente** - Use nível `warn` ou `error` em produção
5. **Use `fastify.inject()` para testes** - Evita overhead de HTTP real
6. **Registre plugins uma vez** - Não re-registre plugins em cada requisição
7. **Use `$refStrategy: 'none'`** - Para schemas simples, evita overhead de referências
