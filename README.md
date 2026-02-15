# Skills

Coleção de **skills** para Claude Code e Cursor, projetadas para elevar a qualidade do código gerado por IA em projetos TypeScript/React/Node.js.

Cada skill ensina a IA a aplicar padrões, boas práticas e prevenção de erros conhecidos em domínios específicos do desenvolvimento frontend e backend.

## O que são Skills?

Skills são arquivos Markdown estruturados (`.claude/skills/`) que fornecem contexto especializado para agentes de IA. Diferente de regras genéricas, cada skill contém:

- **Regras detalhadas** com exemplos de bom e mau uso
- **Prevenção de erros conhecidos** com links para issues reais
- **Padrões de código** prontos para copiar e adaptar
- **Referências de versões** verificadas e atualizadas

## Skills Disponíveis

### Frontend - Best Practices

| Skill                                                                                                   | Regras | Descrição                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| [frontend-react-best-practices](/.claude/skills/frontend-react-best-practices/SKILL.md)                 | 33     | Performance e composição React: otimização de re-renders, bundle size, hooks, error boundaries, compound components, memoização              |
| [frontend-tailwind-best-practices](/.claude/skills/frontend-tailwind-best-practices/SKILL.md)           | 10     | Padrões Tailwind CSS: utilitários de layout (`v-stack`, `h-stack`), color schemes, responsive design, `cn()` para merge de classes           |
| [frontend-accessibility-best-practices](/.claude/skills/frontend-accessibility-best-practices/SKILL.md) | 7      | Acessibilidade (WCAG): HTML semântico, screen readers, navegação por teclado, `reduced-motion`, touch targets                                |
| [frontend-async-best-practices](/.claude/skills/frontend-async-best-practices/SKILL.md)                 | 5      | Otimização assíncrona: eliminação de waterfalls com `Promise.all`, Suspense boundaries, defer/await                                          |
| [frontend-testing-best-practices](/.claude/skills/frontend-testing-best-practices/SKILL.md)             | 6      | Estratégia de testes: E2E (Playwright) sobre unit tests, minimizar mocking, testar comportamento                                             |
| [frontend-design](/.claude/skills/frontend-design/SKILL.md)                                             | -      | Design de interfaces distintas e production-grade: tipografia, paleta de cores, motion, composição espacial. Evita estéticas genéricas de IA |

### Frontend - Bibliotecas

| Skill                                                       | Issues Documentadas | Descrição                                                                                                                                                                           |
| ----------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [tanstack-router](/.claude/skills/tanstack-router/SKILL.md) | 20                  | Routing type-safe e file-based com TanStack Router. Inclui integração com TanStack Query, Better Auth, rotas protegidas, search params com Zod, Virtual Routes e Cloudflare Workers |
| [tanstack-query](/.claude/skills/tanstack-query/SKILL.md)   | 16                  | Server state com TanStack Query v5: `useMutationState`, optimistic updates simplificados, `throwOnError`, network mode offline, migração v4 → v5                                    |

### Backend

| Skill                                                               | Descrição                                                                                                                                                     |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [fastify-better-auth](/.claude/skills/fastify-better-auth/SKILL.md) | Autenticação completa com Fastify + Better Auth: email/password, sessions, middlewares, plugin de username, plugin de organizations com roles e permissões    |
| [fastify-openapi-zod](/.claude/skills/fastify-openapi-zod/SKILL.md) | APIs Fastify com documentação OpenAPI automática via Scalar e validação com schemas Zod. Inclui error handling global, organização por plugins e autenticação |

## Estrutura do Repositório

```
.claude/
└── skills/
    ├── frontend-react-best-practices/
    │   ├── SKILL.md                    # Skill principal (33 regras)
    │   └── rules/                      # Regras individuais detalhadas
    │       ├── rerender-*.md           # Otimização de re-renders (11)
    │       ├── rendering-*.md          # Performance de renderização (10)
    │       ├── composition-*.md        # Padrões de composição (7)
    │       ├── bundle-*.md             # Otimização de bundle (3)
    │       ├── hooks-*.md              # Boas práticas de hooks (2)
    │       ├── client-*.md             # Padrões client-side (2)
    │       └── fault-tolerant-*.md     # Error boundaries (1)
    │
    ├── frontend-tailwind-best-practices/
    │   ├── SKILL.md                    # Skill principal (10 regras)
    │   └── rules/                      # Layout, responsive, color schemes
    │
    ├── frontend-accessibility-best-practices/
    │   ├── SKILL.md                    # Skill principal (7 regras)
    │   └── rules/                      # Semantic HTML, keyboard, screen readers
    │
    ├── frontend-async-best-practices/
    │   ├── SKILL.md                    # Skill principal (5 regras)
    │   └── rules/                      # Parallel, defer, suspense
    │
    ├── frontend-testing-best-practices/
    │   ├── SKILL.md                    # Skill principal (6 regras)
    │   └── rules/                      # E2E, unit, mocking
    │
    ├── frontend-design/
    │   └── SKILL.md                    # Diretrizes de design
    │
    ├── tanstack-router/
    │   ├── SKILL.md                    # Skill principal + 20 issues
    │   ├── README.md
    │   └── references/
    │       └── common-errors.md
    │
    ├── tanstack-query/
    │   ├── SKILL.md                    # Skill principal + 16 issues
    │   ├── README.md
    │   └── references/
    │       ├── best-practices.md
    │       ├── common-patterns.md
    │       ├── testing.md
    │       ├── top-errors.md
    │       ├── typescript-patterns.md
    │       └── v4-to-v5-migration.md
    │
    ├── fastify-better-auth/
    │   ├── SKILL.md                    # Skill principal
    │   ├── README.md
    │   ├── examples.md
    │   └── reference.md
    │
    └── fastify-openapi-zod/
        ├── SKILL.md                    # Skill principal
        ├── README.md
        ├── examples.md
        └── reference.md
```

## Stack Coberta

| Camada           | Tecnologias                     |
| ---------------- | ------------------------------- |
| **Linguagem**    | TypeScript                      |
| **Frontend**     | React, Tailwind CSS             |
| **Routing**      | TanStack Router                 |
| **Server State** | TanStack Query v5               |
| **Backend**      | Fastify                         |
| **Autenticação** | Better Auth                     |
| **Validação**    | Zod                             |
| **Documentação** | OpenAPI / Scalar                |
| **Testes**       | Playwright (E2E), Vitest (Unit) |

## Como Usar

### No Cursor

Copie a pasta `.claude/skills/` para a raiz do seu projeto. O Cursor reconhecerá automaticamente as skills e as aplicará quando relevante.

### No Claude Code

As skills são carregadas automaticamente a partir de `.claude/skills/`. O Claude irá referenciar as regras e padrões ao gerar ou revisar código nos domínios cobertos.

### Seletivamente

Você não precisa usar todas as skills. Copie apenas as pastas das skills relevantes para o seu projeto.

## Números

- **10** skills especializadas
- **61** regras de código detalhadas com exemplos
- **36** issues/erros conhecidos documentados com prevenção
- **89** arquivos de referência no total
