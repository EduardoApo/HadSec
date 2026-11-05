# FortiSIEM 7.5.1.0620 — referências e limites

Pesquisa realizada em 5 de novembro de 2026. Foram consultadas as fontes oficiais relacionadas à construção, consulta, teste e transporte de regras. **Não foi realizada uma auditoria integral de todas as páginas e todos os guias do produto.** Algumas páginas retornaram HTTP 403 ao acesso direto; o conteúdo indexado das fontes oficiais foi usado nos pontos abaixo. Não foi obtido um XSD oficial completo de regras. Posteriormente, a interface do appliance do cliente foi inspecionada e uma regra foi exportada, conforme [análise do ambiente](fortisiem-environment-review.md).

## Fontes oficiais consultadas

| Fonte | Decisão no aplicativo |
| --- | --- |
| [Creating Rules, 7.5.1](https://docs.fortinet.com/document/fortisiem/7.5.1/user-guide/903877/creating-rules) | Diferencia Streaming, Scheduled e Scheduled via SQL. A lógica da regra, ações e exceções não são tratadas como SQL genérico. |
| [Testing a Rule, 7.5.1](https://docs.fortinet.com/document/fortisiem/7.5.1/user-guide/528244/testing-a-rule) | Test Rule exige regra inativa e organização super global. Scheduled e Scheduled via SQL não suportam esse teste; a UI orienta outro procedimento. |
| [Creating a New Advanced Search, 7.5.1](https://docs.fortinet.com/document/fortisiem/7.5.1/user-guide/431900/creating-a-new-advanced-search) | Consultas leem `fsiem.events`; atributos adicionais são selecionados em Attributes used. Recomendação de janela com `phRecvTime`, LIMIT e filtros específicos. |
| [What's New in 7.5.1](https://docs.fortinet.com/document/fortisiem/7.5.1/release-notes/385743/whats-new-in-7-5-1) | Aliases de regras SQL devem começar por letra e conter somente caracteres alfanuméricos. A restrição foi incorporada às verificações. |
| [ClickHouse Usage Notes, 7.5.1](https://docs.fortinet.com/document/fortisiem/7.5.1/user-guide/846327/clickhouse-usage-notes) | A plataforma não tenta reproduzir o otimizador ou as funções específicas do ClickHouse instalado. |
| [Instalação Proxmox, 7.5.1](https://docs.fortinet.com/document/fortisiem/7.5.1/proxmox-installation-guide/131018/fresh-installation) | A documentação identifica os pacotes do build 0620 e a imagem 7.5.1.0620. |
| [Exporting and Importing Rule Definitions, 7.5.0](https://docs.fortinet.com/document/fortisiem/7.5.0/user-guide/476126/exporting-and-importing-rule-definitions) | Fonte da versão anterior sobre transporte XML. A rota equivalente de 7.5.1 retornou 403; a compatibilidade deve ser verificada por importação no build alvo. |
| [Catálogo oficial de regras 7.5.1](https://filestore.fortinet.com/docs.fortinet.com/fsiem/Public_Resource_Access/7_5_1/rules/rule_descriptions.htm) | Referência de detecções e técnicas. Os exemplos do modo demonstrativo não são cópias certificadas dessas regras. |

## O que é verificado

SQL: conteúdo preenchido, limites de tamanho, modo compatível, início SELECT/WITH, referência à tabela de eventos, exclusão de comentários/strings da análise, balanceamento de parênteses/aspas, uma instrução por definição, rejeição de operações de escrita comuns, aliases e cláusulas obviamente incompletas. Avisos para janela temporal e limite de resultados.

XML: documento bem formado, estrutura nativa `rules/DataRequest` confirmada no appliance, uma definição por arquivo, modo consistente, nome e incidente preenchidos, severidade entre 1 e 10, janela positiva para Streaming, subpadrões únicos e referências do incidente. Proíbe DTD/entidades externas e nome reservado `regexp`. Não altera a definição importada.

Essas verificações não constituem um sandbox para executar SQL. O aplicativo **nunca executa a consulta da regra no banco Supabase**. O Supabase guarda o texto para versionamento.

## O que continua dependendo do FortiSIEM

- Gramática completa, funções e semântica específicas da versão do ClickHouse.
- Tipos de eventos, custom event attributes, lookup tables, CMDB, grupos e seleções em Attributes used.
- Ações de incidentes e restrições de atributos reservados, severidade, exceções e condições de limpeza.
- Definição e efeito do agendamento, volume, performance, limite de incidentes e ausência de falsos positivos.
- Compatibilidade de importação do XML e validação pelo engine real.

O exemplo SQL é um ponto de partida, não uma regra pronta para ativar. Confirme nomes dos atributos e o Event Type no catálogo do seu ambiente. Para produção, use XML exportado do build alvo ou finalize a definição SQL pela interface oficial antes de registrar o teste.

## Homologação antes da aprovação

1. Exporte ou prepare a definição no FortiSIEM 7.5.1.0620 e salve uma versão no HadSec Detect.
2. Execute a verificação estática no servidor sobre a versão persistida.
3. Streaming: desative a regra ou use clone inativo, na organização super global; forneça Reporting IP, eventos brutos e pausas no teste oficial.
4. Scheduled/SQL: valide e execute a consulta no Advanced Search e confira agendamento e ações no ambiente de homologação. Não use Test Rule para esses modos.
5. Registre ambiente/build, passos, entradas, resultado esperado e observado. Vincule a evidência à versão exata; falhas posteriores invalidam o aceite até outro teste aprovado.
6. Outro usuário revisa a versão e as evidências. Depois, alguém com permissão de publicação abre o PR.

As evidências são declarações dos responsáveis. A plataforma não atesta automaticamente que um teste foi executado no appliance. A presença de validação estática e de um PR não significa que a regra foi importada, ativada ou validada em produção.
