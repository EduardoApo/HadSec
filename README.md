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

## Formatos e laboratório

O catálogo aceita FortiSIEM XML/SQL, Sigma, KQL Microsoft Kusto, AQL QRadar, EQL Elastic, KQL Kibana, SPL Splunk e YARA. As referências oficiais ficam em **Configurações → Documentação de regras**. A opção de formato determina os parâmetros internos; não é necessário escolher um modo no formulário.

O laboratório faz validação estática parcial e simulação local de eventos. Aceita objeto JSON, lista JSON, NDJSON e texto com campos `chave=valor`. YARA também pode analisar diretamente o texto bruto. Os logs permanecem no navegador; o processamento ocorre em um Web Worker com limite de 2,5 segundos, 200 eventos e 250 KB de entrada.

| Formato | Subconjunto simulado |
|---|---|
| Sigma | Mapas e listas, condições booleanas, `1/all of`, `contains`, `startswith`, `endswith`, `all`, `cased` e `exists` |
| Kusto KQL | Filtros `where`, comparações, listas e operadores de texto/termos; respeita operadores sensíveis e insensíveis a maiúsculas |
| SQL/AQL | Condições `WHERE`, comparações, `LIKE`, `ILIKE`, listas e booleanos |
| EQL | Categoria de evento e filtros de valores, com diferenças entre `==` e `:` |
| Kibana KQL | Comparações em valores JSON tratados como campos `keyword`; o mapping real não é inferido |
| SPL | `search` e `where`, incluindo suas diferenças de precedência e sensibilidade |
| YARA | Strings ASCII literais, `ascii`, `nocase`, `fullword` e condições de strings; não analisa binários ou módulos |
| FortiSIEM XML | Filtro de um subpadrão sem agregação |

O resultado é **Match**, **Sem match** ou **Não suportado**. Correlação, agregações, funções, mappings, módulos, regex e outros recursos fora do subconjunto implementado exigem o motor de destino. Ausência de suporte não é apresentada como uma negativa de detecção. A análise local não substitui a compilação e a homologação no SIEM; a aprovação continua exigindo evidência declarada de teste no destino.

Nas solicitações, **Criar nova regra** registra o formato desejado. **Alterar regra** permite selecionar uma regra cadastrada ou anexar a original. A versão anterior fica imutável, vinculada à solicitação e disponível para comparação e auditoria. A migração `202611080009_multiformat_requests.sql` também impede gateways antigos de validarem formatos que desconhecem.
