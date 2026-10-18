# -*- coding: utf-8 -*-
"""Linha de comandos do Khoza Sec XSS."""

import argparse
import datetime
import sys
import textwrap
from urllib.parse import urlparse

import requests

from . import contextos as C
from . import cookies as CK
from . import relatorio as R
from . import severidade as SEV
from .confirmacao import Confirmador, disponivel
from .crawler import Crawler
from .modelo import Relatorio
from .motores import Motor


LABS = textwrap.dedent("""\
    Laboratórios legais para praticar (feitos para serem testados):
      - https://portswigger.net/web-security  (PortSwigger Academy)
      - http://testphp.vulnweb.com/           (Acunetix, vulnerável de propósito)
      - https://xss-game.appspot.com/          (jogo de XSS da Google)
      - OWASP Juice Shop / DVWA                (instalar localmente)
    Nunca teste sistemas de terceiros sem autorização por escrito.
""")


def _autorizar(alvo, assumir):
    print(R._c("  AUTORIZAÇÃO", R.Cor.BOLD + R.Cor.AMAR))
    print(textwrap.fill(
        "Esta ferramenta envia pedidos de teste — e, se ativar --armazenado, "
        "grava dados de prova — no alvo. Use apenas em sistemas seus ou com "
        "autorização explícita por escrito. O uso não autorizado é ilegal.", 72))
    print(f"\n  Alvo: {R._c(alvo, R.Cor.CIANO)}\n")
    if assumir:
        print(R._c("  Autorização confirmada via --autorizado.\n", R.Cor.VERDE))
        return True
    try:
        resp = input("  Confirma que tem autorização? (escreva SIM): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    ok = resp.strip().upper() == "SIM"
    print(R._c("  Autorização confirmada.\n" if ok else
               "  Não confirmada. A sair.\n", R.Cor.VERDE if ok else R.Cor.VERM))
    return ok


def _cookies_dict(txt):
    d = {}
    if not txt:
        return d
    for par in txt.split(";"):
        if "=" in par:
            k, v = par.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="khoza-sec-xss",
        description="Khoza Sec XSS v2.0 — scanner de XSS (refletido/armazenado/DOM) "
                    "com confirmação de execução e auditoria de cookies.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=LABS)
    p.add_argument("alvo", nargs="?", help="URL inicial a testar")
    p.add_argument("--autorizado", action="store_true",
                   help="confirma autorização de forma não interactiva")
    p.add_argument("--cookie", default=None, help="cookies de sessão: 'k=v; k2=v2'")
    p.add_argument("--profundidade", type=int, default=2, help="profundidade do crawler")
    p.add_argument("--max-paginas", type=int, default=40, help="máx. de páginas a rastrear")
    p.add_argument("--armazenado", action="store_true",
                   help="testa XSS armazenado (grava payloads de prova na app)")
    p.add_argument("--sem-headless", action="store_true",
                   help="não usar navegador; só análise de contexto")
    p.add_argument("--html", metavar="FICHEIRO", help="guardar relatório HTML")
    p.add_argument("--json", metavar="FICHEIRO", help="guardar relatório JSON")
    p.add_argument("--verboso", action="store_true")
    p.add_argument("--sem-cor", action="store_true")
    p.add_argument("--labs", action="store_true", help="lista laboratórios legais e sai")
    args = p.parse_args(argv)

    if args.sem_cor or not sys.stdout.isatty():
        R.Cor.off()
    R.banner()

    if args.labs:
        print(textwrap.indent(LABS, "  "))
        return 0
    if not args.alvo:
        print("  Indique um URL. Ex.:")
        print("    khoza-sec-xss 'http://127.0.0.1:8099/' --autorizado --html rel.html")
        print("  Laboratórios legais:  khoza-sec-xss --labs")
        return 0

    alvo = args.alvo if urlparse(args.alvo).scheme else "http://" + args.alvo
    if not _autorizar(alvo, args.autorizado):
        return 1

    sessao = requests.Session()
    sessao.headers["User-Agent"] = "KhozaSecXSS/2.0 (teste autorizado)"
    cookies = _cookies_dict(args.cookie)
    if cookies:
        sessao.headers["Cookie"] = args.cookie

    rel = Relatorio(alvo=alvo,
                    inicio=datetime.datetime.now().isoformat(timespec="seconds"))

    usar_headless = disponivel() and not args.sem_headless
    rel.headless = usar_headless
    if not usar_headless:
        rel.avisos.append(
            "Confirmação headless desativada: resultados por análise de contexto "
            "(instale 'playwright' e corra 'playwright install chromium' p/ maior precisão).")

    # 1) Rastrear
    print(R._c("  [1/4] A rastrear a aplicação...", R.Cor.AZUL))
    crawler = Crawler(sessao, alvo, max_paginas=args.max_paginas,
                      max_prof=args.profundidade, verboso=args.verboso)
    pontos = Crawler.dedup(crawler.rastrear())
    paginas = sorted(crawler.visitadas)
    print(f"        {len(paginas)} páginas, {len(pontos)} pontos de entrada.")

    # 2) Auditar cookies
    print(R._c("  [2/4] A auditar cookies...", R.Cor.AZUL))
    try:
        r0 = sessao.get(alvo, timeout=10)
        rel.cookies = CK.auditar(r0)
    except Exception as e:
        rel.avisos.append(f"Falha ao auditar cookies: {e}")
    sessao_exposta = any(
        (not c.httponly) and c.severidade in ("Alta", "Média") for c in rel.cookies)

    # 3) Detetar XSS
    print(R._c("  [3/4] A testar XSS (refletido / DOM" +
               (" / armazenado" if args.armazenado else "") + ")...", R.Cor.AZUL))
    cm = Confirmador(cookies=cookies) if usar_headless else None
    if cm:
        cm.__enter__()
    try:
        motor = Motor(sessao, confirmador=cm, verboso=args.verboso,
                      testar_armazenado=args.armazenado)
        for pe in pontos:
            rel.pontos_testados += 1
            rel.achados.extend(motor.refletido(pe))
        for pag in paginas:
            rel.achados.extend(motor.dom(pag))
        rel.achados.extend(motor.armazenado(pontos, paginas))
    finally:
        if cm:
            cm.__exit__()

    # 4) Severidade + relatório
    print(R._c("  [4/4] A calcular severidade e a gerar relatório...", R.Cor.AZUL))
    # de-duplicar achados equivalentes
    vistos, unicos = set(), []
    for a in rel.achados:
        chave = (a.tipo, a.url, a.parametro, a.contexto)
        if chave in vistos:
            continue
        vistos.add(chave)
        unicos.append(a)
    rel.achados = unicos
    for a in rel.achados:
        a.severidade, a.pontuacao = SEV.classificar(a, sessao_exposta)
    rel.achados = SEV.ordenar(rel.achados)
    rel.fim = datetime.datetime.now().isoformat(timespec="seconds")

    R.terminal(rel)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(R.para_html(rel))
        print(R._c(f"  Relatório HTML: {args.html}", R.Cor.VERDE))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(R.para_json(rel))
        print(R._c(f"  Relatório JSON: {args.json}", R.Cor.VERDE))

    n = len(rel.achados)
    print(R._c(f"\n  Concluído: {n} falha(s) XSS. — Khoza Sec XSS v2.0\n",
               R.Cor.BOLD))
    return 0


if __name__ == "__main__":
    sys.exit(main())
