# Implementação funcional dos módulos HadSec

Pedido de 09/11/2026: tornar operacionais as telas existentes, preservando Rule Management, autenticação e design. Publicação somente depois da revisão local do usuário.

## Diagnóstico inicial

- Rule Management: RPCs persistentes, versionamento, aprovação, evidências, GitHub, permissões e auditoria já implementados.
- Dashboard: indicadores existentes de regras e solicitações.
- Coverage, Investigation, Campaigns, False Positives e Query Library: estrutura visual, sem cadastros operacionais ou catálogos.
- Não existe runner de comandos, conector a endpoints ou execução remota de consultas. Isso continua fora do escopo.

## Ordem e critério de avanço

MITRE → SigmaHQ → Atomic → Investigation → Campaigns → False Positives → Query Library. Cada etapa exige testes de banco/permissões, registro real, UI conectada e recarga persistente antes de avançar. Os vínculos entre módulos são exercitados novamente conforme suas entidades ficam disponíveis.

## MITRE ATT&CK

Arquivos: `server/catalog-fetch.mjs`, `server/attack-catalog.mjs`, `server/gateway.mjs`, `src/attack-model.mjs`, `src/operations-api.js`, `src/AttackCoverage.jsx`, `src/OperationsDialog.jsx`, integração em `OperationsWorkspace.jsx`, `main.jsx`, `api.js` e `operations.css`.

Migrações:

- `202611090010_attack_catalog.sql`: técnicas, táticas, relacionamentos, histórico de sincronização, vínculos de regras/testes, permissões e RPCs auditadas.
- `202611090011_attack_sync_guard.sql`: compatibilidade com a proteção `safeupdate` presente no Supabase real.

Sincronização: consulta o commit oficial de `mitre-attack/attack-stix-data`; lê o índice Enterprise e fixa o download nessa revisão; valida STIX, limites e estrutura; calcula SHA-256; publica o snapshot em uma transação. Permissão `catalogs.manage` exigida no servidor e na abertura da sincronização. A publicação da carga é restrita ao servidor. Falhas são registradas e preservam o catálogo anterior.

O snapshot oficial verificado em 09/11/2026 é Enterprise 20.1: 867 técnicas/subtécnicas, 15 táticas e 20.449 relacionamentos; 706 técnicas ativas, excluindo revogadas/depreciadas da matriz. Novas sincronizações podem alterar esses totais.

Cobertura: exige vínculos explícitos de regra e evidência. Evidência de versão antiga é ignorada no estado atual. Revisão manual e simulação local não validam detecção. Resultados divergentes entre ambientes permanecem desconhecidos/insuficientes; o filtro de ambiente permite separar a análise. O estado não é uma taxa ou promessa de cobertura integral da técnica.

Navigator: exporta JSON do schema de layer 4.5, domínio Enterprise, versão ATT&CK, filtros, estado por cor, metadados de commit/data e URL STIX fixada. Não cria percentual artificial.

Testes: `tests/attack.test.js` (modelo de cobertura, limites de importação, RLS, permissões, publicação exclusiva do servidor, vínculos e auditoria); `tests/live-attack.mjs` (fonte oficial, Supabase e navegador reais). Os dados de catálogo e histórico ficam persistidos. A regra temporária é removida e a conta temporária é excluída logicamente para preservar a autoria da sincronização, sem alterar usuários existentes.

Validação manual: entrar → Detection Coverage → Sincronizar MITRE (administrador) → pesquisar T1059.001 → abrir detalhes → vincular uma regra → recarregar → conferir o vínculo → filtrar tática/plataforma/cobertura/ambiente → Navigator JSON. A aba Sincronizações exibe datas, versões, totais e erros reais.

Referências oficiais: [STIX ATT&CK](https://github.com/mitre-attack/attack-stix-data), [schema Navigator 4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md).

Estado e resultados atualizados a cada etapa em `.openai/state/functional-modules.json` (arquivo local ignorado pelo Git).

## SigmaHQ

Migration `202611090014_reference_catalogs.sql`; implementation in `server/official-tar.mjs`, `server/sigma-catalog.mjs`, `src/ReferenceCatalog.jsx` and the shared gateway/UI. The official pinned commit `53b90df66c5b6d1b9be6ba9289c56fe49dd74a73` imported 3,782 rules. Scope: rules, rules-emerging-threats, rules-threat-hunting, rules-dfir and rules-compliance. Deprecated, unsupported and placeholder folders are excluded explicitly. Source authors and DRL 1.1 attribution remain visible. No automatic conversion or deployment.

Validated with `tests/sigma.test.js` (3 tests: YAML safety, bounded TAR, PostgreSQL/RLS/versions/search/links/intake/idempotence) and `tests/live-sigma.mjs` (actual GitHub archive, Supabase, UI, reload and mobile). Original YAML, version hashes and source commits persist; linked intake snapshots cannot drift when the catalog updates. Temporary test rule/request/links removed; catalog and attributed sync history retained.

Manual check: Coverage > SigmaHQ > synchronize > search T1059.001 > view original YAML > relate an internal rule > create a request > reload and inspect the reference hash. Future schema changes remain additive. The user subsequently authorized publication after testing, without another review gate.

## Atomic Red Team

Migrations 202611090015-0018 add private evidence, deduplicated original source files, pinned Atomic request revisions, approval/manual-result/review history and platform filters. Implementation: server/atomic-catalog.mjs, server/evidence.mjs, src/AtomicWorkspace.jsx, src/EvidenceFiles.jsx, plus shared gateway, coverage and APIs. Actual official catalog: 1,950 tests in 353 YAML files. Commands/dependencies remain inert documentation; no runner, endpoint integration or remote execution.

Verified with tests/atomic.test.js (4 tests, including permission/state transitions, cross-subject evidence rejection, SHA/format checks and independent system administrator approval) and tests/live-atomic.mjs using real Supabase and browser sessions. Live coverage: draft/edit, second-user approval through UI, manual record form, private upload and server hash verification, anonymous download denied, result review, retest and persistence after reload. The workflow fixture explicitly did not execute any Atomic command or native SIEM test and did not claim a positive detection. Temporary records, evidence objects and credentials were removed; source catalogs remain.

Manual validation: Coverage > Atomic Red Team > synchronize > open a test > request test > save/edit/submit > reviewer approves > responsible records start > attach evidence > record actual result > reviewer concludes > request a retest. Every transition is authorized/audited in PostgreSQL. Validated coverage requires a completed reviewed result with verified evidence for the current rule version and environment.

Private evidence: 10 MB per file, 50 files/100 MB per subject; original bytes retained, MIME/signatures/UTF-8/size/SHA verified server-side, signed upload with no overwrite, signed downloads expire in 60 seconds, no public bucket policies. Supported files: JSON, NDJSON, CSV, TXT/LOG, PDF, PNG/JPEG. Vercel gateway duration is configured at 300 seconds for catalog synchronization (Hobby Fluid Compute supported); no paid API or new dependency was added.

## Hunting Investigation

Files: `HuntingWorkspace.jsx`, `HuntingForms.jsx`, `HuntingImportForm.jsx`, `HuntingTimeline.jsx`, `hunting-api.js`, `TechniquePicker.jsx`, `operational-report.mjs`, `server/hunting-normalizer.mjs`, `server/hunting-imports.mjs`. Migrations 0019–0021 persist hypotheses, findings, intake links, private originals and versioned event imports. Optimistic edits, permission checks and atomic publication preserve prior timelines on failed imports. Duplicate imports reuse the same mapping snapshot. Original bytes and SHA-256 remain separate from normalized fields. Dates without timezone remain null unless the user explicitly selects a timezone; missing dates require confirmation.

Tests: `tests/hunting.test.js` (4 passing), `tests/live-hunting.mjs` (actual Supabase, Chrome and private Storage). Verified create/edit hypothesis and finding, MITRE/campaign relationships, Hayabusa CSV, Chainsaw JSON, Velociraptor JSONL, explicit timezone, no duplicate events, filters, original download hash, inert imported HTML, change request preserving baseline, conclusion, actual PDF download, reload and mobile. Temporary fixtures removed. No endpoint collection or EVTX parser; artifact-specific fields require confirmed manual mapping. PDF explicitly labels its first-100-event timeline excerpt and includes all case findings and evidence hashes.

Manual: Hunting Investigation > New hypothesis > edit > Evidence > upload structured file > inspect/confirm mapping > Timeline > filters/original > finding > create/change request > conclusion > Reports > PDF. The new publication authorization permits deployment after the remaining modules and regression checks finish.

## Hunting Campaigns

Migration 0022; `src/CampaignWorkspace.jsx`, `src/OperationsShared.jsx`, shared API and styles. Persistent objectives/scope/owners/members/deadlines/priorities, MITRE/rule associations, campaign-linked hypotheses, tasks with six Kanban states, immutable task transition history, actual counts/overdue tasks and closure PDF with evidence hashes. Completing or cancelling a task requires a documented result/reason. Closing a campaign requires all tasks completed/cancelled and a conclusion. Concurrent edits reject stale timestamps. Query version links are added in the query-library stage.

Tests: `tests/campaigns.test.js` (PostgreSQL/RLS, optimistic concurrency, task history, participant assignment and closure guards) and `tests/live-campaigns.mjs` (real create/edit, MITRE + hypothesis links, Kanban movement, reload, completed campaign, downloaded PDF and mobile with no page errors). Temporary campaign/hypothesis/task fixtures removed. Manual: New campaign > save > open > Edit > Kanban > New task > click task and change status/result > Results > closure report. Movement uses an accessible select in the task dialog, including on mobile; no drag-only interaction.

## False Positive Intelligence

Migration 0023; `src/FalsePositiveWorkspace.jsx` and shared operational components. Persistent case, fixed internal-rule identity, responsible/tool/cause, immutable first and subsequent occurrences with exact rule versions, private evidence, recommendations/results with before/after versions and linked tuning requests. New occurrences reopen resolved cases. Effective/ineffective outcomes require evidence from the same case and distinct rule versions. These are attributed analyst evaluations, never native test results or automatic exceptions. Recurrence is the recorded occurrence count beyond the first per case; no rate is claimed without environment totals.

Tests: `tests/false-positives.test.js` (PostgreSQL permissions, versions/baseline, evidence requirements, immutable history and recurrence reopening) and `tests/live-false-positives.mjs` (real UI create/edit, second occurrence, proposed tuning, request preserving baseline, searchable knowledge base, reload and mobile). Temporary records removed. Manual: Register false positive > select rule/version/date > save > attach evidence > New occurrence / Register tuning / Request tuning. No automatic rule edit or SIEM query.

## Hunting Query Library

Migration 0024; `QueryLibraryWorkspace.jsx`, `query-library-model.mjs`, `SubjectQueryLinks.jsx`, reusable `CodeEditor.jsx`. FortiSIEM, Splunk, Elastic, Wazuh, Kusto, QRadar, Velociraptor and other technology metadata; independent language selection; data sources/tags/required fields/MITRE/limitations. Save/edit creates an immutable version with actor, timestamp and revision note. Duplicate creates a new identity. Delete removes the item from the active library and preserves versions/usage. Personal favorites are RLS-isolated. Search/filter operates on actual persisted metadata. JSON export/import uses schema `hadsec.hunting-queries.v1`, 1–20 queries and 2 MB, with nested structure/type/size checks and rejection of unexpected/prototype keys; the database validates independently and rolls back an invalid entire batch. No imported authorship or IDs are trusted. Content remains inert text, without SIEM execution or automatic language conversion.

Version-specific links attach queries to campaigns and hypotheses, including usage notes. Updating/deleting a library query never changes the version used by an investigation. Both subject UIs display/copy the pinned content; reports include authorized query references/text. Tests: `query-library.test.js` (2 passing, parser safety, PostgreSQL/RLS, stale-write rejection, transactional import, personal favorites, duplicate/delete, preserved history and exact usage) and `live-query-library.mjs` (real UI create/edit/copy/duplicate/delete, favorites, JSON round trip, search/filters, campaign+hypothesis display, reload and mobile; no page errors). A browser test found and fixed void-RPC success handling so a successful deletion closes its dialog. Temporary records removed.

Manual: New query > fill metadata/content/note > save > link the current version to a hypothesis/campaign > edit > select the original version to inspect it > open the related subject > inspect its pinned query. Export JSON and import the exported file to create an independent copy. Delete requires confirmation and preserves usage history. Copy uses the browser clipboard and reports permission failures.

## Consolidation and regression

Migration 0025 adds permission-aware `operational_overview` and indexes. Dashboard counts are obtained from persisted records; denied modules return null rather than disclosing counts. Module UIs load on demand, and all phase-one placeholders were removed. Migration 0026 preserves existing links when a rule is archived while rejecting new links to archived rules, verified by `operational-history.test.js`.

No new paid service or dependency was introduced. The existing Supabase/Vercel/GitHub accounts and quotas apply. `tests/review-browser.mjs` retains isolated fixtures solely for regression of existing Rule Management behaviors; all new-module live tests use real Supabase/Auth/Storage and remove only their own temporary business records. Catalog synchronization provenance/audit remains. Existing user passwords and accounts are unchanged. The three unrelated pre-existing local detection-engine/filter/test edits remain outside this release.
