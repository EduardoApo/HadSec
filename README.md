# HadSec Detect

Engenharia e versionamento de regras para **FortiSIEM 7.5.1.0620**. Interface em português, responsiva, com tema escuro e verde-lima inspirado no TryHackMe.

## Funcionalidades

- Contas por usuário e senha, criação administrativa, troca de senha no painel e troca obrigatória no primeiro acesso.
- Exclusão de contas com confirmação pelo usuário exato e preservação do histórico. Conta atual e administradores do sistema são protegidos.
- Perfis Administrador, Engenheiro, Revisor e Leitor; criação de perfis personalizados com permissões individuais.
- Permissões globais por perfil, com exceções por usuário: herdar, permitir ou bloquear. As exceções prevalecem nas RPCs, nas funções do servidor e na interface.
- Nomes e descrições das permissões editáveis pelo administrador; as chaves internas permanecem estáveis para preservar os controles de acesso.
- Menu compacto por padrão no desktop, tooltips por opção e expansão persistida no navegador. No celular, o menu abre completo.
- Definições XML preservadas e consultas SQL ClickHouse, versões imutáveis e hash SHA-256.
- Solicitações de ajustes, discussão e associação de uma versão validada. Perfis comuns exigem outro revisor; o Administrador do sistema pode aprovar o próprio trabalho, com justificativa, evidência e auditoria.
- Comparação entre versões, importação e download da definição.
- Laboratório de análise estática; evidências de homologação vinculadas à versão.
- Aprovação exige teste declarado no FortiSIEM; revisão manual isolada não libera publicação.
- Branch exclusivo e pull request no GitHub, com autorização no servidor, bloqueio de concorrência e recuperação de tentativas interrompidas.
- Auditoria de ações e exportação JSON; RLS habilitada em todas as tabelas do aplicativo.

## Executar

Requer Node.js 22.13+ e npm. Este workspace também contém uma distribuição portátil do Node em `../.tools/`.

```sh
npm ci
cp .env.example .env
# Preencha as variáveis do seu projeto Supabase.
npm run dev
```

O painel exige autenticação no Supabase. Não há modo demonstração, sessão simulada ou base local alternativa. Sem URL/chave pública válidas, o acesso permanece bloqueado. Preferências antigas de demonstração são removidas do navegador e não autorizam nenhuma operação.

Os campos de senha oferecem mostrar/ocultar no login, na criação de contas e na troca de senha, sem alterar o valor informado.

## Hospedar no Vercel

Importe este repositório com a branch `main`, diretório raiz do repositório e preset **Vite**. O arquivo `vercel.json` define `npm ci`, `npm run build` e saída em `dist`.

Em **Settings → Environment Variables**, configure para **Production** e **Preview**:

| Variável | Valor |
| --- | --- |
| `VITE_SUPABASE_URL` | URL raiz do seu projeto, igual ao `.env` local |
| `VITE_SUPABASE_ANON_KEY` | Chave pública `sb_publishable_...` ou chave legada `anon` |

`VITE_SUPABASE_PUBLISHABLE_KEY` também é aceito no lugar de `VITE_SUPABASE_ANON_KEY`. Se ambos estiverem definidos, a chave `ANON_KEY` tem precedência. Remova valores antigos para evitar conectar ao projeto errado.

O `.env` local fica fora do Git e não é transferido para o Vercel. O Vite incorpora as variáveis públicas na compilação: após alterar valores, execute **Redeploy**. Uma compilação no Vercel falha com uma mensagem explícita se a configuração estiver ausente ou inválida. O login usa Supabase Auth; validação persistida, exclusão de regras e GitHub usam a rota autenticada `/api/gateway` no Vercel.

No servidor, configure `SUPABASE_URL`, uma chave `SUPABASE_SERVICE_ROLE_KEY` ou `SUPABASE_SECRET_KEY`, e uma chave pública `SUPABASE_ANON_KEY` ou `SUPABASE_PUBLISHABLE_KEY`. Os nomes públicos `VITE_SUPABASE_*` também são aceitos pelo servidor como alternativa para a URL e a chave pública. Integrações Supabase no Vercel podem já fornecer essas variáveis. Para o GitHub, configure `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` e `GITHUB_BASE_BRANCH`. Todos devem apontar para o projeto e o repositório de regras já utilizados.

Nunca adicione prefixo `VITE_` a senhas, `DATABASE_URL`, chaves de servidor ou tokens. O middleware local do Vite atende à mesma rota com os valores do `.env`, sem incorporá-los ao JavaScript do navegador. A função Edge permanece como adaptador opcional do mesmo código, sem ser exigida pelo frontend do Vercel. A documentação da [API Node no Vercel](https://vercel.com/docs/frameworks/frontend/vite) descreve o diretório `api/` utilizado aqui.

Referências: [variáveis no Vercel](https://vercel.com/docs/environment-variables) e [variáveis e modos no Vite](https://vite.dev/guide/env-and-mode).

## Supabase

Use um projeto dedicado. O provisionamento interrompe se detectar uma tabela `profiles` preexistente sem o marcador do HadSec, para não afetar outra aplicação.

No `.env`:

```dotenv
VITE_SUPABASE_URL=https://SEU_PROJETO.supabase.co
VITE_SUPABASE_ANON_KEY=SUA_CHAVE_PUBLICAVEL
SUPABASE_URL=https://SEU_PROJETO.supabase.co
SUPABASE_SERVICE_ROLE_KEY=SUA_CHAVE_SERVICE_ROLE
DATABASE_URL=postgresql://postgres:SENHA_CODIFICADA@db.SEU_PROJETO.supabase.co:5432/postgres
SUPABASE_ACCESS_TOKEN=SEU_TOKEN_DE_GERENCIAMENTO
APP_ORIGIN=https://ORIGEM_EXATA_DO_FRONTEND
BOOTSTRAP_USERNAME=HadSec
BOOTSTRAP_PASSWORD=SENHA_INICIAL
BOOTSTRAP_EMAIL=hadsec@hadsec.local
```

A chave publicável (`sb_publishable_...`) também funciona no campo `VITE_SUPABASE_ANON_KEY`. O nome foi mantido para compatibilidade com instalações que usam a chave anon. A senha na URL PostgreSQL precisa de percent-encoding, por exemplo `@` → `%40`. Não adicione prefixo `VITE_` a qualquer segredo.

```sh
npm run provision -- inspect
npm run provision -- migrate
npm run provision -- configure
npm run bootstrap
npm run provision -- deploy
```

`migrate` aplica a migração e um marcador de execução. Com token, usa a API oficial de gerenciamento; sem token, usa PostgreSQL com TLS e a CA oficial em `certs/supabase-root.crt`. `configure` obtém a chave de serviço por API autenticada e a grava apenas no `.env` ignorado. `bootstrap` cria o administrador uma única vez e **não redefine** uma senha existente. `deploy` empacota e publica a função `gateway` e os secrets listados, sem Docker.

Se a chave de serviço ainda não estiver disponível, `bootstrap` pode criar somente o administrador inicial pela conexão PostgreSQL configurada. Esse procedimento de instalação usa uma transação, não promove contas existentes e valida o resultado no Supabase Auth. A troca de senha usa `auth.updateUser` com verificação da senha atual; um trigger protegido libera o perfil após a alteração. Login e troca de senha não dependem da Edge Function `gateway`.

Alternativamente, aplique a migração pelo Supabase CLI e execute `supabase functions deploy gateway --no-verify-jwt`. A função valida o JWT com `auth.getUser()` e verifica perfil/permissões em todas as ações. `verify_jwt=false` permite as chaves publicáveis modernas sem remover a verificação de identidade implementada na função.

Contas internas usam `usuario@hadsec.local` apenas como identidade do Supabase Auth. O login aceita usuário ou e-mail; não há dependência de entrega de e-mail. Criação, atualização e exclusão de contas usam RPCs PostgreSQL protegidas por `users.manage`, com senha criptografada por bcrypt, criação transacional da identidade/perfil, revogação de sessões na desativação e preservação do histórico na exclusão. Essas operações não dependem da Edge Function. `node --env-file=.env tests/live-accounts.mjs` verifica o ciclo completo com contas temporárias removidas ao final.

## GitHub

No `.env` local e nas variáveis de servidor do Vercel, configure `GITHUB_OWNER`, `GITHUB_REPO`, `GITHUB_BASE_BRANCH` (padrão `main`) e `GITHUB_TOKEN`. O repositório deve existir com um commit na branch base. Token com acesso somente ao repositório, permissões **Contents: Read and write**, **Pull requests: Read and write** e Metadata de leitura. O comando `npm run provision -- deploy` atualiza apenas o adaptador Edge opcional; o Vercel recebe seus próprios valores de ambiente no redeploy.

Uma publicação cria `hadsec/<id-da-solicitação>` e grava `rules/<id-da-regra>/v<N>.xml` ou `.sql`. O PR registra versão, hash e parecer. O aplicativo não faz merge e não ativa regras no SIEM. Se um PR for fechado sem merge, reabra-o antes de repetir o envio.

O repositório de código do site e o repositório de regras são independentes. `.env`, tokens, senha e evidências de testes de navegador não entram no Git. O arquivo `.env.example` contém somente nomes e exemplos sem credenciais.

## Validação FortiSIEM

Leia [docs/fortisiem-7.5.1.md](docs/fortisiem-7.5.1.md). A validação é **estática e parcial**, não um compilador Fortinet, XSD oficial ou execução no SIEM. A documentação consultada não permite garantir ausência de falhas em todas as consultas ou em atributos personalizados do seu ambiente.

A [inspeção do ambiente real](docs/fortisiem-environment-review.md) confirmou o formato XML `rules/DataRequest`. O importador preenche metadados a partir desse formato e o painel exibe condições, incidente e dependências preservadas no arquivo.

XML preserva uma definição completa exportada do FortiSIEM. SQL representa a consulta de uma regra Scheduled via SQL; ações de incidente, atributos usados e agendamento precisam ser conferidos e configurados no FortiSIEM. Um arquivo SQL isolado não é uma definição XML importável. Não há endpoints FortiSIEM inventados ou chamadas a APIs de IA pagas.

## Testar e compilar

```sh
npm test
npm run check:gateway
npm run build
```

Os testes executam o validador e a migração real em PostgreSQL embarcado (PGlite), com papéis e `auth.uid()` controlados. Verificam RLS, proibição de escrita direta, concorrência de versões, hash, aprovação por outra pessoa, evidências, bloqueio de publicação duplicada e senha inicial. Não substituem uma homologação no serviço Supabase hospedado.

Para os testes de navegador, inicie `npm run dev` e execute `node tests/browser.mjs`. O script usa Chrome instalado no caminho Windows informado no arquivo; adapte `executablePath` em outros sistemas. Verifica bloqueio de acesso sem login, remoção do estado antigo e mostrar/ocultar senha em desktop e celular. `node --env-file=.env tests/live-auth.mjs` verifica login e troca de senha com uma conta temporária no Supabase, removida ao final. As capturas ficam em `artifacts/`, fora do Git.

## Arquitetura

React + Vite no navegador → Supabase Auth/PostgREST com JWT e RLS → RPCs PostgreSQL para contas e transições protegidas. A rota Node `/api/gateway` executa a análise estática sobre o conteúdo persistido, arquiva regras de teste e integra o GitHub. Ela verifica o usuário, a conta ativa, a troca de senha inicial e as permissões individuais em cada requisição. O adaptador Edge opcional usa o mesmo `server/gateway.mjs`. A chave de serviço nunca chega ao navegador. Cada versão tem conteúdo, autor, justificativa e hash; qualquer ajuste gera outra versão.

## Revisão da interface e do fluxo

A revisão de 06/11/2026 permanece local até aprovação da publicação. Execute `npm run dev` e abra `http://127.0.0.1:5173`. O login continua real; não existe modo demonstração. `node tests/review-browser.mjs` testa os novos fluxos com serviços interceptados exclusivamente pelo Playwright, sem tocar no banco real. Capturas ficam em `artifacts/review/`, fora do Git.

Exclusão de regra exige `rules.write` e confirmação do nome exato. Ela marca `rules.archived`, preservando versões e auditoria. Regras ligadas a solicitações em andamento ou publicadas são protegidas.

A criação pelo detalhe de uma solicitação carrega seu contexto no editor; ao salvar uma versão válida, a plataforma a vincula à solicitação existente. Falhas posteriores ao salvamento não mantêm um formulário que possa duplicar a versão. As notificações gerais são atualizadas ao focar a janela, abrir o sino e a cada 45 segundos; o estado de leitura é local e separado por usuário. A rota retorna apenas resumos de ações permitidas, sem liberar a auditoria completa a perfis sem `audit.read`.

Configurações do sistema reúne conexões e informações da ferramenta. A senha fica em Meu perfil. A verificação de conexões consulta Auth, banco com o JWT do usuário e branch GitHub; disponibilidade, latência e momento da consulta vêm das respostas reais. A página Relatórios calcula indicadores e gráficos dos registros visíveis no período, com exportação CSV. Não há dados demonstrativos no produto. O splash preenche a coruja de acordo com as consultas concluídas.

A aprovação administrativa depende da migração `202611060006_admin_approval.sql`, preparada para aplicar somente após aprovação da publicação. Ela mantém a separação para outros perfis, exige validação e teste real, e grava `administrator_self_approval` na auditoria. A conexão do código é `EduardoApo/HadSec`; o destino privado de regras é `EduardoApo/hadsec-detect-rules`.

`node --env-file=.env tests/live-gateway.mjs` executa o teste integrado explícito na prévia: cria uma conta e uma regra temporárias, verifica login real, persistência da validação, exclusão pelo navegador, auditoria e acesso de leitura ao GitHub. Os registros temporários são removidos ao final, sem criar PRs ou alterar contas existentes.

Bibliotecas utilizadas são gratuitas. Supabase e GitHub estão sujeitos aos limites dos planos utilizados; o projeto não contrata planos ou APIs pagas. Configure cópias de segurança e retenção de acordo com a sua operação; exclusão de evidências e auditoria não é exposta ao usuário.
