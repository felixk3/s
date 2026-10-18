# Khoza Sec XSS v2.0

Scanner profissional de **Cross-Site Scripting (XSS)** em Python, para a equipa
de segurança testar as próprias aplicações de forma **autorizada e controlada**.
Mostra tudo no terminal (em português) e exporta relatório **HTML** e **JSON**.

Deteta **XSS refletido, armazenado e baseado em DOM**, confirma a execução real
num **navegador headless** (elimina falsos positivos), audita a **segurança dos
cookies** e atribui **severidade** a cada falha — para o relatório aos
developers ser preciso e acionável.

> **Filosofia:** a ferramenta prova a falha com um marcador **inofensivo** e
> confirma que o código executa. Não embute roubo de sessão nem exfiltração —
> para documentar o risco com rigor basta provar a execução e mostrar que o
> cookie não tem HttpOnly. É assim que trabalham o Burp e o OWASP ZAP.

## O que faz

| Capacidade | Detalhe |
|---|---|
| Crawler | Rastreia a app (mesmo domínio, profundidade configurável) e descobre URLs, parâmetros GET/POST e formulários |
| XSS refletido | Testa cada parâmetro, identifica o **contexto** (corpo HTML, atributo, `<script>`, URL, comentário) e os caracteres que passam sem codificação |
| XSS armazenado | Injeta prova via POST, deteta **persistência** noutras páginas e confirma execução |
| XSS DOM | Análise estática de **fontes → sumidouros** (`location.hash`/`search` → `innerHTML`/`eval`/…) e confirmação via fragmento |
| Confirmação real | Abre a página no **Chromium headless** e verifica se o payload **executou mesmo** |
| Auditoria de cookies | HttpOnly, Secure, SameSite e âmbito — mostra se um XSS conseguiria roubar a sessão |
| Severidade | Modelo transparente (tipo + contexto + execução confirmada + exposição de sessão) → Crítica/Alta/Média/Baixa |
| Relatórios | Terminal a cores, **HTML** profissional e **JSON** para integrar noutras ferramentas |

## Instalação

```bash
pip install -r requirements.txt
python3 -m playwright install chromium   # para a confirmação de execução
```

Sem o Playwright a ferramenta ainda funciona, mas em modo "só análise de
contexto" (menos preciso) — avisa quando isso acontece.

## Uso

```bash
# Ver laboratórios legais para praticar
python3 khoza_sec_xss.py --labs

# Scan completo, com relatório HTML e JSON
python3 khoza_sec_xss.py "http://127.0.0.1:8099/" --autorizado \
    --html relatorio.html --json relatorio.json

# Incluir teste de XSS armazenado (grava payloads de prova na app)
python3 khoza_sec_xss.py "http://meu-alvo-autorizado/" --autorizado --armazenado

# Área autenticada
python3 khoza_sec_xss.py "http://.../app" --autorizado --cookie "PHPSESSID=abc; outro=1"
```

### Opções principais

| Opção | Para quê |
|---|---|
| `--autorizado` | confirma autorização sem perguntar |
| `--armazenado` | testa XSS armazenado (escreve dados de prova) |
| `--cookie "k=v; ..."` | sessão autenticada |
| `--profundidade N` | profundidade do crawler (padrão 2) |
| `--max-paginas N` | limite de páginas (padrão 40) |
| `--html FICH` / `--json FICH` | exporta o relatório |
| `--sem-headless` | desativa o navegador (só contexto) |
| `--verboso` | mostra o processo |
| `--labs` | lista laboratórios legais |

## Testar localmente (laboratório incluído)

```bash
python3 lab_local.py &        # alvo vulnerável em 127.0.0.1:8099 (refletido, armazenado, DOM, cookie inseguro)
python3 khoza_sec_xss.py "http://127.0.0.1:8099/" --autorizado --armazenado --html rel.html
```

Veja `relatorio_exemplo.html` e `relatorio_exemplo.json` para um exemplo de saída.

## Ética e legalidade

Use **apenas** em sistemas seus ou com **autorização explícita por escrito**. O
uso não autorizado é ilegal. A ferramenta pede confirmação de autorização por
esse motivo. O guia `PROCESSO_PENTEST.md` descreve o processo completo.

## Estrutura

```
khoza_sec_xss.py        lançador (= python3 -m khozaxss)
khozaxss/
  cli.py                linha de comandos e orquestração
  crawler.py            descoberta de pontos de entrada
  contextos.py          análise de contexto e payloads de prova
  motores.py            deteção: refletido / armazenado / DOM
  confirmacao.py        confirmação de execução (Playwright headless)
  cookies.py            auditoria de cookies
  severidade.py         cálculo de severidade
  relatorio.py          relatório terminal / HTML / JSON
  modelo.py             estruturas de dados
lab_local.py            laboratório vulnerável para testes locais
PROCESSO_PENTEST.md     passo a passo de um pentest
```

## Limites honestos

- O XSS **armazenado** é testado nos formulários POST encontrados; fluxos com
  vários passos (ex.: confirmação, moderação) podem exigir teste manual.
- A deteção **DOM** cobre os padrões `fonte → sumidouro` mais comuns em scripts
  inline; lógica muito dinâmica ou em ficheiros externos pode exigir revisão
  manual.
- Nenhum scanner substitui um pentester. Esta ferramenta acelera e dá precisão;
  o julgamento humano continua a ser necessário.
```
