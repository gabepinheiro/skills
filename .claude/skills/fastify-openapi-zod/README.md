# Fastify + OpenAPI + Zod Skill

Skill para criar APIs REST com Fastify, documentação automática via OpenAPI com Scalar UI, e validação de schemas com Zod.

## Quando usar esta skill

Esta skill é automaticamente aplicada quando você:

- Mencionar Fastify, OpenAPI, Swagger ou Zod
- Criar endpoints REST
- Configurar documentação de API
- Implementar validação de schemas

## O que esta skill oferece

- **Setup inicial**: Configuração do Fastify com Swagger/OpenAPI e Scalar
- **Schemas Zod**: Padrões para criar schemas de validação com Zod
- **Documentação OpenAPI**: Integração automática com OpenAPI 3.0
- **Rotas tipadas**: TypeScript type-safe usando inferência do Zod
- **Error handling**: Tratamento de erros de validação e negócio
- **Organização**: Padrões para estruturar rotas, schemas e plugins
- **Autenticação**: Exemplos com JWT e hooks de autenticação
- **Melhores práticas**: Padrões consolidados da comunidade

## Estrutura da skill

- **SKILL.md**: Instruções principais, setup, padrões básicos e checklist
- **examples.md**: Exemplos completos de implementação (CRUD, autenticação, upload)
- **reference.md**: Referência de plugins, configurações avançadas e patterns do Zod

## Arquivos gerados

Ao usar esta skill, você criará uma estrutura como:

```
src/
├── server.ts          # Setup do Fastify com plugins
├── routes/
│   ├── users.ts       # Rotas de usuários
│   └── index.ts       # Registro de rotas
└── schemas/
    ├── users.ts       # Schemas Zod de usuários
    └── common.ts      # Schemas reutilizáveis
```

## Principais dependências

```bash
bun add fastify @fastify/swagger @scalar/fastify-api-reference zod zod-to-json-schema
```

## Início rápido

Veja o SKILL.md para instruções passo-a-passo de como:

1. Configurar o Fastify com OpenAPI
2. Criar schemas Zod
3. Criar rotas documentadas
4. Implementar validação e error handling
5. Organizar o código em plugins

## Documentação adicional

- [Fastify Documentation](https://www.fastify.io/)
- [Zod Documentation](https://zod.dev/)
- [OpenAPI Specification](https://swagger.io/specification/)
