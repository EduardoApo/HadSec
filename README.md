# HadSec

**Security Detection Rule Management Platform**

Plataforma web para gerenciamento, versionamento, validação e revisão colaborativa de regras de detecção, desenvolvida para apoiar operações de Security Operations Center (SOC).

O HadSec centraliza o ciclo de vida das regras de segurança, oferecendo rastreabilidade, controle de acesso e integração com GitHub.

## Funcionalidades

- **Gerenciamento de regras:** criação, edição, importação e organização de regras de detecção.
- **Controle de versões:** histórico imutável, comparação de alterações e integridade por SHA-256.
- **Validação estática:** análise de definições XML e consultas SQL utilizadas no FortiSIEM.
- **Workflow de aprovação:** solicitações, revisões, evidências de homologação e decisões auditáveis.
- **Controle de acesso:** perfis personalizados e permissões individuais.
- **Integração com GitHub:** criação de branches e pull requests para publicação controlada.
- **Auditoria e relatórios:** rastreamento de atividades, indicadores e exportação de relatórios.

## Tecnologias

| Camada | Tecnologia |
|---|---|
| Frontend | React, Vite |
| Backend | Node.js |
| Banco de dados | PostgreSQL / Supabase |
| Autenticação | Supabase Auth |
| Controle de acesso | Row Level Security (RLS) |
| Versionamento | Git / GitHub |
| Deploy | Vercel |
| Relatórios | jsPDF |

## Instalação

**Pré-requisitos:** Node.js 22.13+ e npm.

Clone o repositório:

```bash
git clone https://github.com/EduardoApo/HadSec.git
cd HadSec
```

Instale as dependências:

```bash
npm ci
```

Configure as variáveis de ambiente:

```bash
cp .env.example .env
```

Configure o Supabase e os serviços necessários conforme a documentação do projeto.

Inicie o ambiente de desenvolvimento:

```bash
npm run dev
```

## Testes

```bash
npm test
npm run check:gateway
npm run build
```

## Arquitetura

A aplicação utiliza React e Vite no frontend, Supabase para autenticação e persistência de dados e uma camada de servidor para operações protegidas e integração com GitHub.

O controle de acesso é aplicado tanto na interface quanto no backend e no banco de dados.

## Observações

O mecanismo de validação FortiSIEM realiza análises estáticas e parciais. Ele não substitui testes de homologação no ambiente real.

O HadSec não ativa regras automaticamente no SIEM e não realiza merge automático de pull requests.

## Autor

Desenvolvido por [EduardoApo](https://github.com/EduardoApo).
