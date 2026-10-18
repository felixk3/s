# -*- coding: utf-8 -*-
"""Geração de relatórios: terminal, HTML e JSON."""

import dataclasses
import html
import json
import textwrap

from . import contextos as C
from .cookies import REMEDIACAO_COOKIE


class Cor:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    VERDE = "\033[92m"; VERM = "\033[91m"; AMAR = "\033[93m"
    AZUL = "\033[94m"; CIANO = "\033[96m"; CINZA = "\033[90m"
    _on = True

    @classmethod
    def off(cls):
        for n in ("RESET", "BOLD", "DIM", "VERDE", "VERM", "AMAR",
                  "AZUL", "CIANO", "CINZA"):
            setattr(cls, n, "")
        cls._on = False


def _c(t, cor):
    return f"{cor}{t}{Cor.RESET}"


COR_SEV = {
    "Crítica": Cor.VERM, "Alta": Cor.VERM, "Média": Cor.AMAR,
    "Baixa": Cor.AZUL, "Informativa": Cor.CINZA,
}


REMEDIACAO = {
    "refletido": textwrap.dedent("""\
        Codificação de saída conforme o contexto (correção principal):
          - Corpo HTML: converta < > & " ' em entidades (&lt; &gt; ...).
          - Atributo: codifique aspas e use sempre aspas à volta do valor.
          - JavaScript: não injete dados do utilizador dentro de <script>;
            se precisar, use JSON.stringify e escape \\uXXXX.
          - URL: valide o esquema (bloqueie javascript:) e use encodeURIComponent.
        Reforce com validação de entrada (lista branca) e uma Content Security
        Policy (script-src 'self'). Marque cookies de sessão com HttpOnly."""),
    "armazenado": textwrap.dedent("""\
        XSS armazenado é dos mais graves: o payload fica guardado e atinge todos
        os utilizadores que veem o conteúdo. Corrija codificando na SAÍDA (ao
        mostrar), não só na entrada. Codifique conforme o contexto de exibição,
        aplique validação por lista branca no registo e uma CSP restritiva.
        Considere sanitização com uma biblioteca madura (ex.: DOMPurify) quando
        precisa mesmo de permitir algum HTML."""),
    "dom": textwrap.dedent("""\
        XSS baseado em DOM ocorre no próprio JavaScript do lado do cliente.
        Evite passar dados controláveis (location.hash/search, document.URL,
        window.name) para sumidouros perigosos (innerHTML, document.write, eval).
        Use APIs seguras: textContent em vez de innerHTML; para HTML necessário,
        sanitize com DOMPurify. Ative Trusted Types quando possível."""),
}

IMPACTO = textwrap.dedent("""\
    Um atacante cria um pedido/link com o payload e leva a vítima a abri-lo (ou,
    no caso armazenado, basta a vítima ver a página). O código corre no domínio
    confiável da aplicação, com a sessão da vítima, e pode: ler o cookie de
    sessão se não tiver HttpOnly, agir em nome da vítima, registar o que ela
    escreve ou redirecioná-la. Por isso o XSS ataca cada utilizador que confia
    na aplicação. Esta ferramenta prova a falha com um marcador inofensivo — não
    rouba dados.""")


# ----------------------------------------------------------------- TERMINAL
BANNER = r"""
 _  _ _  _ ___ ______ ____    ____ ____ ____    _  _ ____ ____
 |_/  |__| |  |  /__|   |      [__  |___ |        \/  [__  [__
 | \_ |  | |__| .    .  |__.   ___] |___ |___    _/\_ ___] ___]
"""


def banner():
    print(_c(BANNER, Cor.CIANO))
    print(_c("  Khoza Sec XSS v2.0", Cor.BOLD) +
          _c("  — scanner profissional de XSS (refletido / armazenado / DOM)",
             Cor.DIM))
    print(_c("  Uso exclusivo em sistemas autorizados.\n", Cor.CINZA))


def terminal(rel):
    print(_c("\n  ════════════════ RELATÓRIO ════════════════", Cor.CIANO))
    print(f"  Alvo: {rel.alvo}")
    print(f"  Início: {rel.inicio}   Fim: {rel.fim}")
    modo = "com confirmação headless" if rel.headless else \
           "só análise de contexto (headless indisponível)"
    print(f"  Modo: {modo}")
    print(f"  Pontos de entrada testados: {rel.pontos_testados}")
    for av in rel.avisos:
        print(_c("  ! " + av, Cor.AMAR))

    # XSS
    print(_c("\n  ── Vulnerabilidades XSS ──", Cor.BOLD))
    if not rel.achados:
        print(_c("  Nenhuma confirmada. (Continue com testes manuais p/ DOM e "
                 "armazenado.)", Cor.VERDE))
    for i, a in enumerate(rel.achados, 1):
        cs = COR_SEV.get(a.severidade, Cor.CINZA)
        print()
        print(_c(f"  #{i}  [{a.severidade}  {a.pontuacao}/10]  XSS {a.tipo}", cs + Cor.BOLD))
        print(f"      URL:       {a.url}")
        print(f"      Método:    {a.metodo}")
        print(f"      Parâmetro: {a.parametro}")
        print(f"      Contexto:  {a.contexto}")
        conf = {True: _c("SIM (navegador executou o payload)", Cor.VERM),
                False: "não executou no navegador",
                None: "não confirmado (sem headless)"}[a.executou]
        print(f"      Executa:   {conf}")
        if a.caracteres_livres:
            print(f"      Caracteres livres: {' '.join(a.caracteres_livres)}")
        print(f"      {_c('Como foi encontrada:', Cor.BOLD)}")
        print(textwrap.indent(textwrap.fill(C.EXPLICACAO.get(a.contexto, ""), 66),
                              "        "))
        if a.nota_extra:
            print(textwrap.indent(textwrap.fill(a.nota_extra, 66), "        "))
        print(f"      {_c('Prova (trecho):', Cor.BOLD)} {_c(a.trecho[:120], Cor.CINZA)}")
        print(f"      {_c('Payload de prova:', Cor.BOLD)} {_c(a.payload_prova, Cor.AMAR)}")
        print(f"      {_c('Correção:', Cor.BOLD)}")
        print(textwrap.indent(REMEDIACAO.get(a.tipo, ""), "        "))

    # Cookies
    print(_c("\n  ── Segurança de cookies ──", Cor.BOLD))
    if not rel.cookies:
        print(_c("  Nenhum cookie definido na resposta analisada.", Cor.CINZA))
    for ck in rel.cookies:
        cs = COR_SEV.get(ck.severidade, Cor.CINZA)
        flags = f"HttpOnly={ck.httponly}  Secure={ck.secure}  SameSite={ck.samesite}"
        print(_c(f"  • {ck.nome}  [{ck.severidade}]  {flags}", cs))
        for p in ck.problemas:
            print(textwrap.indent(textwrap.fill(p, 66), "      - "))
    if any(c.problemas for c in rel.cookies):
        print(_c("  Correção: ", Cor.BOLD) + REMEDIACAO_COOKIE)

    print(_c("\n  ── Impacto (geral) ──", Cor.BOLD))
    print(textwrap.indent(IMPACTO, "  "))
    print()


# --------------------------------------------------------------------- JSON
def para_json(rel):
    return json.dumps(dataclasses.asdict(rel), ensure_ascii=False, indent=2)


# --------------------------------------------------------------------- HTML
def para_html(rel):
    e = html.escape
    linhas = []
    linhas.append(f"""<!doctype html><html lang="pt"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Khoza Sec XSS — Relatório</title>
<style>
 :root{{--bg:#0f1419;--card:#1a212b;--txt:#e6edf3;--dim:#8b98a5;--line:#2d3742;
   --crit:#ff5c5c;--alta:#ff8a5c;--media:#ffce54;--baixa:#5ca8ff;--info:#8b98a5;--ok:#3fb950;}}
 *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--txt);
   font:15px/1.6 system-ui,Segoe UI,Roboto,sans-serif;padding:24px;max-width:1000px;margin:auto}}
 h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:17px;border-bottom:1px solid var(--line);
   padding-bottom:6px;margin-top:32px}}
 .sub{{color:var(--dim);font-size:13px}}
 .kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
 .kpi{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}}
 .kpi b{{font-size:22px;display:block}}
 .card{{background:var(--card);border:1px solid var(--line);border-left-width:4px;
   border-radius:10px;padding:16px;margin:14px 0}}
 .Critica{{border-left-color:var(--crit)}} .Alta{{border-left-color:var(--alta)}}
 .Media{{border-left-color:var(--media)}} .Baixa{{border-left-color:var(--baixa)}}
 .Informativa{{border-left-color:var(--info)}}
 .tag{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}}
 .t-Critica{{background:var(--crit);color:#1a0000}} .t-Alta{{background:var(--alta);color:#1a0a00}}
 .t-Media{{background:var(--media);color:#1a1500}} .t-Baixa{{background:var(--baixa);color:#001022}}
 .t-Informativa{{background:var(--info);color:#0a0f14}}
 code,pre{{background:#0b0f14;border:1px solid var(--line);border-radius:6px;padding:2px 6px;
   font-family:ui-monospace,Menlo,monospace;font-size:13px;overflow:auto}}
 pre{{padding:10px;white-space:pre-wrap;word-break:break-word}}
 .meta{{color:var(--dim);font-size:13px}} table{{border-collapse:collapse;width:100%}}
 td,th{{border:1px solid var(--line);padding:8px;text-align:left;font-size:13px}}
 .exec-sim{{color:var(--crit);font-weight:700}} .exec-nao{{color:var(--dim)}}
 .foot{{color:var(--dim);font-size:12px;margin-top:40px;border-top:1px solid var(--line);padding-top:12px}}
</style></head><body>
<h1>Khoza Sec XSS — Relatório de Segurança</h1>
<div class="sub">Alvo: {e(rel.alvo)} &nbsp;·&nbsp; {e(rel.inicio)} → {e(rel.fim)} &nbsp;·&nbsp;
 Modo: {"confirmação headless" if rel.headless else "só análise de contexto"}</div>""")

    n_crit = sum(1 for a in rel.achados if a.severidade in ("Crítica", "Alta"))
    linhas.append(f"""<div class="kpis">
 <div class="kpi"><b>{len(rel.achados)}</b>falhas XSS</div>
 <div class="kpi"><b>{n_crit}</b>alta/crítica</div>
 <div class="kpi"><b>{rel.pontos_testados}</b>pontos testados</div>
 <div class="kpi"><b>{len(rel.cookies)}</b>cookies</div></div>""")

    if rel.avisos:
        linhas.append("<p class='meta'>Avisos: " +
                      "; ".join(e(a) for a in rel.avisos) + "</p>")

    linhas.append("<h2>Vulnerabilidades XSS</h2>")
    if not rel.achados:
        linhas.append("<p>Nenhuma confirmada automaticamente.</p>")
    for i, a in enumerate(rel.achados, 1):
        sev_cls = a.severidade.replace("í", "i").replace("é", "e")
        execu = {True: '<span class="exec-sim">SIM — o navegador executou o payload</span>',
                 False: '<span class="exec-nao">não executou no navegador</span>',
                 None: '<span class="exec-nao">não confirmado (sem headless)</span>'}[a.executou]
        livres = " ".join(a.caracteres_livres)
        linhas.append(f"""<div class="card {sev_cls}">
 <span class="tag t-{sev_cls}">{e(a.severidade)} · {a.pontuacao}/10</span>
 &nbsp;<b>XSS {e(a.tipo)}</b>
 <table>
  <tr><th>URL</th><td><code>{e(a.url)}</code></td></tr>
  <tr><th>Método</th><td>{e(a.metodo)}</td></tr>
  <tr><th>Parâmetro</th><td><code>{e(a.parametro)}</code></td></tr>
  <tr><th>Contexto</th><td>{e(a.contexto)}</td></tr>
  <tr><th>Executa</th><td>{execu}</td></tr>
  {"<tr><th>Caracteres livres</th><td><code>"+e(livres)+"</code></td></tr>" if livres else ""}
 </table>
 <p><b>Como foi encontrada:</b> {e(C.EXPLICACAO.get(a.contexto,''))}
 {(' '+e(a.nota_extra)) if a.nota_extra else ''}</p>
 <p><b>Prova (trecho da resposta):</b></p><pre>{e(a.trecho[:300])}</pre>
 <p><b>Payload de prova:</b></p><pre>{e(a.payload_prova)}</pre>
 <p><b>Impacto:</b> {e(IMPACTO)}</p>
 <p><b>Correção:</b></p><pre>{e(REMEDIACAO.get(a.tipo,''))}</pre>
</div>""")

    linhas.append("<h2>Segurança de cookies</h2>")
    if not rel.cookies:
        linhas.append("<p>Nenhum cookie definido na resposta analisada.</p>")
    else:
        linhas.append("<table><tr><th>Cookie</th><th>HttpOnly</th><th>Secure</th>"
                      "<th>SameSite</th><th>Severidade</th><th>Problemas</th></tr>")
        for ck in rel.cookies:
            probs = "<br>".join(e(p) for p in ck.problemas) or "—"
            linhas.append(f"<tr><td><code>{e(ck.nome)}</code></td>"
                          f"<td>{ck.httponly}</td><td>{ck.secure}</td>"
                          f"<td>{e(ck.samesite)}</td><td>{e(ck.severidade)}</td>"
                          f"<td>{probs}</td></tr>")
        linhas.append("</table>")
        linhas.append(f"<p><b>Correção:</b> {e(REMEDIACAO_COOKIE)}</p>")

    linhas.append(f"""<div class="foot">Gerado por Khoza Sec XSS v2.0 — ferramenta
     de teste de segurança para uso autorizado. Os payloads usados são inofensivos
     (apenas provam execução). Não reproduza falhas fora do âmbito autorizado.</div>
    </body></html>""")
    return "".join(linhas)
