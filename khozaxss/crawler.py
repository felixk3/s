# -*- coding: utf-8 -*-
"""Crawler de profundidade limitada, restrito ao mesmo domínio."""

from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

from bs4 import BeautifulSoup

from .modelo import PontoEntrada


def _mesmo_dominio(a, b):
    return urlparse(a).hostname == urlparse(b).hostname


def _normalizar(url):
    p = urlparse(url)
    return urlunparse(p._replace(fragment=""))


class Crawler:
    def __init__(self, sessao, base, max_paginas=40, max_prof=2, verboso=False):
        self.s = sessao
        self.base = base
        self.max_paginas = max_paginas
        self.max_prof = max_prof
        self.verboso = verboso
        self.visitadas = set()
        self.pontos = []

    def _log(self, m):
        if self.verboso:
            print(f"  [crawler] {m}")

    def rastrear(self):
        fila = deque([(self.base, 0)])
        while fila and len(self.visitadas) < self.max_paginas:
            url, prof = fila.popleft()
            url = _normalizar(url)
            if url in self.visitadas or prof > self.max_prof:
                continue
            if not _mesmo_dominio(url, self.base):
                continue
            self.visitadas.add(url)
            try:
                r = self.s.get(url, timeout=10)
            except Exception as e:
                self._log(f"falhou {url}: {e}")
                continue
            ct = r.headers.get("Content-Type", "")
            if "html" not in ct:
                continue
            self._log(f"{url}  ({len(self.visitadas)}/{self.max_paginas})")
            self._extrair(url, r.text)
            # novos links
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                destino = urljoin(url, a["href"])
                if _mesmo_dominio(destino, self.base):
                    fila.append((destino, prof + 1))
        return self.pontos

    def _extrair(self, url, html):
        # 1) Parâmetros no próprio URL (GET)
        p = urlparse(url)
        q = parse_qs(p.query)
        if q:
            base = urlunparse(p._replace(query=""))
            self.pontos.append(PontoEntrada(
                "GET", base, {k: v[0] for k, v in q.items()},
                origem=f"URL {url}"))

        # 2) Formulários
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            metodo = (form.get("method") or "GET").upper()
            destino = urljoin(url, form.get("action") or url)
            campos = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                nome = inp.get("name")
                if not nome:
                    continue
                tipo = (inp.get("type") or "").lower()
                if tipo in ("submit", "button", "image", "reset", "file"):
                    continue
                campos[nome] = inp.get("value") or "teste"
            if campos:
                self.pontos.append(PontoEntrada(
                    metodo, destino, campos, origem=f"formulário em {url}"))

    @staticmethod
    def dedup(pontos):
        vistos, saida = set(), []
        for pe in pontos:
            chave = (pe.metodo, _normalizar(pe.url),
                     tuple(sorted(pe.parametros.keys())))
            if chave in vistos:
                continue
            vistos.add(chave)
            saida.append(pe)
        return saida
