# Análise do ambiente FortiSIEM

Inspeção visual e por acessibilidade em 5 de novembro de 2026, autorizada pelo usuário. Leitura da tela Resources → Rules e exportação de uma única regra de sistema. Nenhuma definição foi alterada ou ativada e nenhum teste foi executado no appliance.

## Confirmado na interface

- Versão **7.5.1.0620**, armazenamento **ClickHouse**, organização **Super**, escopo **Global**.
- A listagem informou **3.070 regras**, com paginação de 200 registros naquele momento.
- Escopo de regra **System** ou **User**; severidade, táticas e tags de incidente na listagem.
- Ações disponíveis: New, Edit, Clone, Export, Import, Test e Refresh. Apenas visualização e Export foram utilizados.
- Detalhes incluem fonte de dados, tecnologia de detecção, modo de avaliação, técnica MITRE, remediação, condições, janela, incidente gerado, watch lists e atributos disparadores.
- O menu oferece Event Types, Watch Lists, Lookup Tables, Reports e outros catálogos. Sua existência foi observada; não foi realizada uma coleta completa dos conteúdos desses catálogos.

## Formato real de exportação

A regra **Account Locked: Domain** foi exportada localmente. Sua estrutura é:

```xml
<rules>
  <DataRequest mode="Streaming" tactic="…" technique="…">
    <Name>…</Name>
    <Description>…</Description>
    <PatternClause window="600">
      <SubPattern name="…">
        <SingleEvtConstr>…</SingleEvtConstr>
        <GroupEvtConstr>…</GroupEvtConstr>
        <GroupByAttr>…</GroupByAttr>
      </SubPattern>
    </PatternClause>
    <IncidentDef eventType="…" severity="6" fireFreq="86400">
      <ArgList>…</ArgList>
    </IncidentDef>
    <DynWatchLists>…</DynWatchLists>
  </DataRequest>
</rules>
```

O XML original fica somente em `artifacts/`, ignorado pelo Git. A forma nativa é `rules/DataRequest`, com essa capitalização. A primeira implementação do validador foi corrigida a partir desta evidência.

## Aproveitado no HadSec Detect

1. **Importação nativa**: reconhecimento de `rules/DataRequest` e preenchimento de nome, descrição, técnica, severidade e modo na criação.
2. **Resumo da definição**: leitura de evento do incidente, fonte de dados, tecnologia, táticas, janela, frequência de notificação, tags, watch lists, agrupamentos e atributos disparadores diretamente do XML versionado.
3. **Validação estrutural**: modo consistente, incidente e severidade definidos, janela válida para Streaming, subpadrões únicos e referências corretas no mapeamento do incidente.
4. **Dependências explícitas**: referências como `Group@…` e watch lists geram aviso. O texto é preservado; não é substituído por nomes amigáveis ou consultas inventadas.
5. **Conteúdo completo por versão**: condições, ações e listas dinâmicas continuam no XML, em vez de guardar apenas um filtro.

O XML exportado passou pela versão `hadsec-static-2` do validador. Isso confirma as verificações implementadas, sem atestar a execução da regra em produção.

## Próximas coletas úteis

| Recurso | Uso no HadSec | Condição |
| --- | --- | --- |
| Event Attributes | Autocomplete e checagem dos nomes/tipos reais do ambiente | Obter catálogo e formatos de exportação; não assumir atributos personalizados |
| Event Types e grupos | Detectar referências ausentes no destino | Coletar identificadores estáveis, não somente nomes exibidos |
| Lookup Tables e Watch Lists | Manifesto de dependências por versão | Versionar esquema e referência; conteúdos sensíveis precisam de escopo definido |
| XML de regras User | Baseline das detecções customizadas e comparação após mudanças | Importar individualmente ou implementar lote com histórico por regra |
| Test Results / homologação SQL | Evidências anexadas ao hash aprovado | Manter teste e execução ligados ao modo correto |
| Analytics | Exemplos do SQL e funções suportadas no appliance | Validar no engine real; não executar consultas de investigação sem escopo |

Não foram criados tokens FortiSIEM, ativadas integrações ou presumidos endpoints privados de sincronização. Uma sincronização automatizada exige confirmar os endpoints oficialmente suportados e o acesso de serviço apropriado.
