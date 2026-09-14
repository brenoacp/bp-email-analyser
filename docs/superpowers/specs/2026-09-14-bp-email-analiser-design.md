# Especificação Técnica de Design: bp-email-analiser

**Data:** 2026-09-14  
**Status:** Aprovado  
**Autor:** Antigravity (Google DeepMind) & Breno  
**Projeto:** `bp-email-analiser`  
**Repositório/Diretório:** `/home/breno/bp-email-analiser`

---

## 1. Visão Geral e Objetivos

O **bp-email-analiser** é uma aplicação web forense de segurança projetada para analistas de SOC, pesquisadores e equipes de resposta a incidentes (DFIR). Seu objetivo é realizar a ingestão, desmontagem e análise aprofundada de cabeçalhos de e-mail (RFC 5322 e RFC 5321), mapeando todo o caminho de rede percorrido pela mensagem, auditando autenticações criptográficas (SPF, DKIM, DMARC, ARC), identificando anomalias sintáticas e vetores de falsificação de identidade (BEC, spoofing, typosquatting), inspecionando vereditos de gateways de segurança corporativos (Microsoft 365, Exchange, Google Workspace, SEGs) e atribuindo uma **Pontuação de Risco/Fraude (0 a 100)** fundamentada em evidências técnicas claras e exportáveis em relatórios para SOC (PDF e JSON).

---

## 2. Arquitetura do Sistema

A solução adota uma arquitetura desacoplada de alto desempenho:
- **Backend**: FastAPI (Python 3.12) assíncrono, operando um pipeline concorrente via `asyncio.gather` para consultas de rede externas e motor forense modular.
- **Frontend**: Single Page Application (SPA) moderna em React 18, Vite, TypeScript e Tailwind CSS, equipada com componentes visuais interativos (mapa Leaflet com rota de saltos, velocímetro de risco, badges de autenticação, linha do tempo e inspetor de cabeçalhos brutos).
- **Sem persistência sensível**: A análise ocorre 100% em memória, respeitando privacidade e confidencialidade corporativa.

```
bp-email-analiser/
├── backend/
│   ├── app/
│   │   ├── main.py                     # Entry point FastAPI, middlewares CORS, rota raiz
│   │   ├── core/
│   │   │   ├── config.py               # Timeouts, limites de taxa, chaves opcionais
│   │   │   └── schemas.py              # Modelos Pydantic v2 (Request, Response, Findings)
│   │   ├── analyzers/
│   │   │   ├── hops_analyzer.py        # Cadeia Received:, cálculo de latência e FCrDNS
│   │   │   ├── identity_analyzer.py    # From, Return-Path, Reply-To, Typosquatting, BEC
│   │   │   ├── auth_analyzer.py        # SPF, DKIM, DMARC, ARC (cabeçalhos e DNS ao vivo)
│   │   │   ├── client_analyzer.py      # Message-ID, X-Mailer, Date vs Received drift
│   │   │   ├── seg_analyzer.py         # M365 (SCL/BCL/CAT), Exchange AuthAs, Google, SEGs
│   │   │   ├── enrichment.py           # RDAP/Whois assíncrono, GeoIP, ASN e MX check
│   │   │   └── rbl_analyzer.py         # Consulta de reputação de IP em DNSBL/RBLs públicas
│   │   ├── engine/
│   │   │   ├── scoring.py              # Motor de pontuação de fraude ponderado (0-100)
│   │   │   └── report_generator.py     # Gerador de relatório em PDF estruturado
│   │   └── api/
│   │       └── routes.py               # POST /api/analyze, GET /api/export-pdf, GET /api/samples
│   ├── tests/                          # Testes unitários com fixtures de e-mails
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── HeaderInput.tsx         # Textarea e Drag & Drop de arquivo .eml
│   │   │   ├── RiskGauge.tsx           # Velocímetro visual animado do score de 0-100
│   │   │   ├── HopsTimeline.tsx        # Linha do tempo dos saltos com latência e status
│   │   │   ├── HopsMap.tsx             # Mapa mundi Leaflet traçando os saltos de IP
│   │   │   ├── AuthBadges.tsx          # Status de SPF, DKIM, DMARC e ARC
│   │   │   ├── IdentityCard.tsx        # Auditoria From/Return-Path/Reply-To e alertas BEC
│   │   │   ├── SegCard.tsx             # Métricas M365 (SCL/BCL/CAT) e gateways
│   │   │   ├── WhoisPanel.tsx          # Informações do domínio e IP de origem
│   │   │   └── RawHeaderViewer.tsx     # Visualizador com busca e quebra de linha
│   │   ├── services/
│   │   │   └── api.ts                  # Cliente Axios / Fetch tipado
│   │   ├── types/
│   │   │   └── email.ts                # Definições TypeScript dos schemas da API
│   │   ├── App.tsx
│   │   ├── index.css
│   │   └── main.tsx
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   └── vite.config.ts
├── docs/
│   └── superpowers/specs/
│       └── 2026-09-14-bp-email-analiser-design.md
└── README.md
```

---

## 3. Especificação dos Módulos Analisadores

### 3.1. Cadeia de Saltos (`Received:`) & FCrDNS (`hops_analyzer.py`)
- **Extração de Hops**: Mapeia todas as cláusulas `Received:`, invertendo a lista da ordem física (último salto ao primeiro) para a ordem cronológica real (do salto de origem até o MTA de borda do destinatário).
- **Cálculo de Latência**: Subtrai os timestamps RFC 2822 de saltos consecutivos para medir o tempo de trânsito entre MTAs (em segundos/minutos). Latências anômalas (> 30 minutos sem motivo justificado) geram alerta.
- **FCrDNS (Forward-Confirmed reverse DNS)**:
  1. Para cada IP público extraído dos saltos:
     - Realiza consulta PTR reversa (ex: `in-addr.arpa` / `ip6.arpa`).
     - Realiza consulta direta `A` / `AAAA` para o nome de host obtido.
     - Confere se o IP resultante fecha o ciclo com o IP original do salto.
  2. Identifica se o hostname do PTR condiz com pools dinâmicos/residenciais (ex: `*.dsl.*`, `*.dynamic.*`, `*.cable.*`).

### 3.2. Enriquecimento de IP e Domínio (`enrichment.py` e `rbl_analyzer.py`)
- **Detecção do IP de Origem**: Primeiro IP público que aparece no salto mais antigo da cadeia `Received:`. IPs das redes privadas RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) são catalogados como *Rede Local/Interna* e não sofrem consultas externas.
- **Geolocalização & ASN**:
  - Consulta assíncrona ao endpoint HTTP de GeoIP gratuito (ex: `ip-api.com/json/{ip}` ou similar com fallback).
  - Extrai: país, código ISO, cidade, latitude, longitude, ASN e nome da organização/ISP.
- **RDAP / Whois do Domínio**:
  - Consulta endpoints oficiais de RDAP (ICANN Bootstrap / Registro.br / RIPE).
  - Extrai data de registro/criação, data de expiração, registrador credenciado e país de cadastro.
  - Calcula a **Idade do Domínio** em dias. Domínios com idade `< 30 dias` ou `< 90 dias` são marcados com alto risco de *burner domain*.
- **Verificação de Registros MX**:
  - Consulta se o domínio emissor possui registros MX válidos. Domínios sem registro MX ou com MX apontando para `127.0.0.1` são sinalizados como anomalia grave.
- **Listas Negras DNSBL / RBL (`rbl_analyzer.py`)**:
  - Consulta o IP de origem em listas de reputação públicas consolidadas: `zen.spamhaus.org`, `b.barracudacentral.org` e `bl.spamcop.net` via consulta DNS assíncrona.
  - Identifica códigos de retorno (ex: 127.0.0.2 a 127.0.0.11 do Spamhaus para SBL, XBL, PBL).

### 3.3. Autenticação de E-mail (`auth_analyzer.py`)
- **Inspeção de Cabeçalhos Locais**: Extrai resultados registrados pelos MTAs receptores em `Authentication-Results` e `Received-SPF`.
- **Validação DNS ao Vivo**:
  - **SPF**: Consulta o registro TXT `v=spf1` do domínio do `Return-Path`. Avalia os mecanismos (`ip4`, `ip6`, `include`, `redirect`, `all`).
  - **DKIM**: Inspeciona a assinatura em `DKIM-Signature` (extraindo domínio `d=`, seletor `s=` e algoritmo `a=`). Faz consulta DNS de chave pública em `<selector>._domainkey.<d>` e valida alinhamento de domínio com o `From:`.
  - **DMARC**: Consulta `_dmarc.<domain>`, identifica a política (`p=none`, `p=quarantine`, `p=reject`), política de subdomínio (`sp=`) e alinhamento de identificadores (SPF Alignment e DKIM Alignment).
  - **ARC**: Valida blocos `ARC-Seal`, `ARC-Message-Signature` e `ARC-Authentication-Results` (cv=none, cv=pass, cv=fail) para analisar se o e-mail passou por retransmissores legítimos.

### 3.4. Identidade, Spoofing & BEC (`identity_analyzer.py`)
- **From vs Return-Path (Envelope-From)**: Compara o domínio no cabeçalho `From:` com o domínio do `Return-Path` (RFC 5321 vs 5322).
- **Display Name Spoofing (BEC)**: Extrai a parte textual do remetente (ex: `"Diretoria TI <atacante@gmail.com>"`). Se contiver termos de autoridade ou marcas conhecidas (Financeiro, CEO, Suporte, Microsoft, Google, etc.) combinados com domínios gratuitos de webmail, dispara alerta crítico de BEC.
- **Reply-To & Typosquatting**:
  - Verifica se o `Reply-To:` direciona as respostas para outro domínio.
  - Executa algoritmo de distância de Levenshtein e verificação de caracteres homóglifos entre o domínio do `From:` e o domínio do `Reply-To:` para alertar sobre typosquatting (ex: `paypal.com` vs `paypa1.com`).
- **Sender vs From**: Detecta se um agente transmissor (`Sender:`) não autorizado está enviando em nome do autor (`From:`).

### 3.5. Metadados do Cliente & Sintaxe (`client_analyzer.py`)
- **Message-ID**: Avalia se o identificador segue a RFC 5322 (`<uuid@domain>`) e se o domínio gerador coincide ou possui relação com o domínio emissor.
- **X-Mailer / User-Agent**: Mapeia o cliente de disparo. Sinaliza ferramentas de disparo em massa ou scripts (ex: PHPMailer, python-requests, Outlook Express legado, etc.).
- **Date vs Received (Timestamp Drift)**: Calcula a diferença entre a data declarada no cliente (`Date:`) e o timestamp do primeiro salto (`Received:`). Diferenças superiores a 2 horas ou fusos horários incompatíveis geram alerta de manipulação temporal.
- **Inspeção MIME de Anexos Perigosos**: Avalia declarações nos cabeçalhos `Content-Type:` e `Content-Disposition:` quanto a arquivos com extensões de risco (`.exe`, `.scr`, `.vbs`, `.iso`, `.bat`, `.xlsm`, `.hta`, `.one`).

### 3.6. Vereditos de Gateways e SEGs (`seg_analyzer.py`)
- **Microsoft 365 (`X-Forefront-Antispam-Report`)**:
  - Decodifica:
    - **SCL** (Spam Confidence Level): -1 (legítimo interno) a 9 (spam de alta probabilidade).
    - **BCL** (Bulk Complaint Level): 0 a 9.
    - **CAT** (Category): `CAT:PHSH` (Phishing), `CAT:SPM` (Spam), `CAT:MALW` (Malware).
    - **SFV** (Spam Filtering Verdict): `SFV:SKS` (Bypass por regra de transporte), `SFV:SPM`.
- **Microsoft Exchange**: Avalia `X-MS-Exchange-Organization-AuthAs` (`Internal` vs `Anonymous`).
- **Google Workspace**: Avalia `X-Google-Smtp-Source` e `X-Gm-Message-State`.
- **Sandboxes e Reescrita de URLs**: Detecta cabeçalhos de gateways corporativos como Proofpoint TAP (`X-Proofpoint-Virus-Version`), Defender Safe Links e Mimecast.

---

## 4. Motor de Risco (Risk Engine) & Pontuação

A pontuação total é calculada pela soma ponderada dos achados forenses, limitada ao teto de 100 pontos:

$$\text{Score Total} = \min\left(100, \sum \text{Pontos dos Achados}\right)$$

### 4.1. Tabela de Pesos por Evidência

| Categoria | Evidência Identificada | Pontuação |
|---|---|:---:|
| **Autenticação** | Falha de SPF (`Fail` ou `Permerror`) | +20 |
| | SPF `Softfail` ou `Neutral` | +10 |
| | Falha de DKIM / Assinatura inválida | +20 |
| | Domínio sem registro SPF ou sem assinatura DKIM | +10 |
| | Falha de DMARC (`dmarc=fail`) com política de quarentena/rejeição | +20 |
| | Falha de DMARC com política permissiva (`p=none`) | +10 |
| | Quebra na cadeia ARC em mensagem retransmitida | +10 |
| **Identidade & BEC** | Display Name Spoofing detectado (nome corporativo em webmail gratuito) | +30 |
| | Typosquatting ou similaridade homoglífica no `Reply-To` | +25 |
| | Divergência entre `From:` e `Return-Path` (Envelope Spoofing) | +15 |
| | `Sender:` inconsistente com o `From:` | +10 |
| **Infraestrutura** | IP de origem listado em lista negra ativa (Spamhaus / Barracuda / SpamCop) | +25 |
| | Domínio registrado há menos de 30 dias | +20 |
| | Domínio registrado entre 30 e 90 dias | +10 |
| | Domínio emissor sem registros MX ou com MX nulo (`127.0.0.1`) | +20 |
| | Falha de FCrDNS no salto de origem (PTR não fecha com A/AAAA) | +15 |
| | IP de origem pertencente a pool dinâmico residencial (ADSL/Cable) | +10 |
| **Metadados & SEGs** | Microsoft 365 com flag explícita de Phishing (`CAT:PHSH` ou `CAT:MALW`) | +25 |
| | Microsoft 365 com SCL >= 5 | +15 |
| | Extensão de anexo de alto risco declarada no MIME (`.exe`, `.iso`, `.vbs`, etc.) | +20 |
| | Descompasso temporal (`Date:` vs `Received:`) superior a 2 horas | +10 |
| | `X-Mailer` indicando script de disparo automatizado ou bot de spam | +10 |
| | Formato de `Message-ID` malformado ou desconexo do MTA | +10 |

### 4.2. Faixas de Severidade e Classificação

- **0 a 25 — Seguro / Risco Baixo (Verde)**: Nenhuma inconformidade grave. Autenticação válida e domínios consistentes.
- **26 a 50 — Informativo / Risco Moderado (Amarelo)**: Pequenos desvios (ex: e-mail legítimo de marketing sem DMARC restritivo). Exige atenção.
- **51 a 75 — Alto Risco / Provável Ameaça (Laranja)**: Múltiplas falhas críticas combinadas (ex: SPF falho + domínio recente + Reply-To divergente).
- **76 a 100 — Crítico / Fraude Confirmada (Vermelho)**: Indicadores inequívocos de BEC, phishing direcionado, malware anexado ou IP listado em RBL com veredito de gateway condenatório.

---

## 5. Interface do Usuário (UI/UX)

- **Tema Visual**: Interface profissional com alternador Dark/Light Mode.
- **Ingestão**:
  - Textarea com highlight de sintaxe e limpeza automática de espaços vazios.
  - Drag & Drop de arquivos `.eml` com leitura direta em JavaScript via FileReader.
  - Botão de carga de amostras rápidas (Legítimo vs Phishing Bancário vs BEC Corporativo).
- **Dashboard de Resultados**:
  - **Gauge Interativo**: Medidor animado de 0 a 100 com badge de severidade e contador de tempo de execução.
  - **Aba Resumo**: Lista de achados priorizada, recomendação de resposta a incidentes e botões de exportação (PDF e JSON).
  - **Aba Hops & Mapa**: Mapa mundi Leaflet com marcadores e linhas conectando os saltos, associado a uma tabela cronológica detalhada com FCrDNS e latências.
  - **Aba Autenticação**: Cards interativos de SPF, DKIM, DMARC e ARC, exibindo o registro DNS consultado e a verificação local.
  - **Aba Identidade**: Auditoria visual de `From:`, `Return-Path:`, `Reply-To:`, `Sender:` e análise de similaridade.
  - **Aba Metadados & Gateways**: Diagnóstico de M365 (SCL/BCL/CAT), Exchange, Google e cabeçalhos de segurança adicionais.
  - **Aba Cabeçalho Bruto**: Visualizador formatado com quebra de linha, busca por termos e cópia com um clique.

---

## 6. Especificação dos Endpoints da API

### `POST /api/analyze`
- **Request Body**:
  ```json
  {
    "raw_header": "Received: from ...\nFrom: ...\nTo: ...",
    "options": {
      "live_dns": true,
      "rdap_lookup": true,
      "rbl_check": true
    }
  }
  ```
- **Response**: JSON contendo:
  - `summary`: Score total, nível de risco, tempo de análise, recomendação executiva.
  - `findings`: Lista de evidências encontradas com descrição, categoria e pontos adicionados.
  - `hops`: Lista de saltos com ordem, IP, hostname, FCrDNS, localização, ASN e latência.
  - `authentication`: Status de SPF, DKIM, DMARC e ARC com registros DNS.
  - `identity`: From, Return-Path, Reply-To, similaridade, alerta de BEC.
  - `domain_info`: Idade do domínio, registrar, país, data de criação, MX records.
  - `origin_ip`: IP, país, cidade, coordenadas, ASN, status em RBLs.
  - `client_metadata`: Message-ID, X-Mailer, Date vs Received drift.
  - `seg_verdicts`: M365 SCL/BCL/CAT, Exchange AuthAs, Google markers, sandboxes.

### `GET /api/export-pdf`
- Gera e retorna o arquivo binário `application/pdf` do relatório técnico para SOC.

### `GET /api/samples/{id}`
- Retorna cabeçalhos de teste prontos (`legitimate`, `phishing_banking`, `bec_executive`, `botnet_spam`).

---

## 7. Resiliência, Segurança e Tratamento de Erros

- **Timeouts**: Consultas assíncronas externas (DNS, RDAP, GeoIP, RBL) possuem timeout máximo de **2.5 segundos** por requisição. Em caso de falha de conexão, o item é marcado como `Consulta Indisponível` sem abortar a requisição principal.
- **Tratamento de IPs Privados**: IPs das faixas RFC 1918 e Loopback são detectados imediatamente e dispensados de consultas externas de GeoIP/RDAP/RBL.
- **Parsing Tolerante**: Decodificação de cabeçalhos RFC 2047 com suporte a múltiplos encodings (UTF-8, ISO-8859-1) e linhas multiline (*folded headers*).
- **Segurança e Privacidade**: Nenhuma mensagem ou cabeçalho é persistido em disco ou banco de dados. Sanitização de saída no React para evitar injeção XSS.

---

## 8. Estratégia de Testes

- **Testes Unitários (Pytest)**:
  - `test_hops_analyzer.py`: Ordenação cronológica de saltos, cálculo de latência e lógica FCrDNS.
  - `test_identity_analyzer.py`: Regras de BEC, divergência From/Return-Path, detecção de typosquatting via Levenshtein.
  - `test_auth_analyzer.py`: Combinações de SPF (Pass, Softfail, Fail), DMARC (None, Quarantine, Reject) e ARC.
  - `test_scoring.py`: Validação matemática da soma de pesos e limites de faixas (0 a 100).
- **Testes de Integração da API**:
  - Testes com fixtures de e-mails reais contra o endpoint `POST /api/analyze`.
  - Teste de geração e integridade do relatório PDF (`GET /api/export-pdf`).
