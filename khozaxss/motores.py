# -*- coding: utf-8 -*-
"""Motores de deteção: XSS refletido, armazenado e baseado em DOM."""

import re
from urllib.parse import urlencode, urljoin

from bs4 import BeautifulSoup

from . import contextos as C
from .modelo import Achado


# --- fontes e sumidouros para análise DOM estática ---------------------------
FONTES_DOM = [
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "location",
]
SUMIDOUROS_DOM = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "insertAdjacentHTML", "eval", "setTimeout", "setInterval",
    "Function", "\\.html\\(", "srcdoc",
]


class Motor:
    def __init__(self, sessao, confirmador=None, verboso=False,
                 testar_armazenado=False):
        self.s = sessao
        self.conf = confirmador
        self.verboso = verboso
        self.flag_armazenado = testar_armazenado

    def _log(self, m):
        if self.verboso:
            print(f"  [motor] {m}")

    def _pedir(self, metodo, url, params):
        try:
            if metodo == "GET":
                return self.s.get(url, params=params, timeout=10)
            return self.s.post(url, data=params, timeout=10)
        except Exception as e:
            self._log(f"erro {metodo} {url}: {e}")
            return None

    # ---------------------------------------------------------------- REFLETIDO
    def refletido(self, pe):
        achados = []
        for nome in list(pe.parametros.keys()):
            marcador = C.novo_marcador()
            params = dict(pe.parametros)
            params[nome] = marcador
            r = self._pedir(pe.metodo, pe.url, params)
            if not r or marcador not in r.text:
                continue

            contexto, trecho = C.detetar_contexto(r.text, marcador)

            m1, m2 = C.novo_marcador(), C.novo_marcador()
            params2 = dict(pe.parametros)
            params2[nome] = C.sonda_caracteres(m1, m2)
            r2 = self._pedir(pe.metodo, pe.url, params2)
            livres = C.caracteres_livres(r2.text, m1, m2) if r2 else []

            if not C.parece_exploravel(contexto, livres):
                self._log(f"{nome}: reflete em {contexto} mas parece codificado")
                continue

            token = C.novo_marcador("tok")
            payload = C.payload_prova(contexto, token)
            executou = self._confirmar(pe.metodo, pe.url, pe.parametros,
                                       nome, payload, token)

            achados.append(Achado(
                tipo="refletido", url=pe.url, metodo=pe.metodo, parametro=nome,
                contexto=contexto, caracteres_livres=livres, trecho=trecho.strip(),
                payload_prova=payload, executou=executou))
            self._anunciar("refletido", pe.url, nome, contexto, executou)
        return achados

    def _confirmar(self, metodo, url, params_base, nome, payload, token):
        if not self.conf:
            return None
        params = dict(params_base)
        params[nome] = payload
        if metodo == "GET":
            url_full = url + ("&" if "?" in url else "?") + urlencode(params)
            return self.conf.confirmar_get(url_full, token)
        return self.conf.confirmar_post(url, params, token)

    # --------------------------------------------------------------- ARMAZENADO
    def armazenado(self, pontos, paginas):
        """
        Injeta um payload de prova em campos de formulários POST, depois procura
        onde ele ficou guardado (nas páginas rastreadas) e confirma execução.
        Escreve dados na app — por isso só corre com --armazenado.
        """
        achados = []
        if not self.flag_armazenado:
            return achados
        for pe in pontos:
            if pe.metodo != "POST":
                continue
            for nome in list(pe.parametros.keys()):
                # Passo 1: marcador simples (sem HTML) -> saber se persiste e em
                # que contexto aparece (sem contaminar o contexto com o payload).
                marcador = C.novo_marcador()
                dados = dict(pe.parametros)
                dados[nome] = marcador
                self._log(f"armazenado: a sondar {pe.url} campo {nome}")
                if self._pedir("POST", pe.url, dados) is None:
                    continue
                pag_persist, contexto, trecho = None, None, ""
                for pag in [pe.url] + list(paginas):
                    rp = self._pedir("GET", pag, {})
                    if rp is not None and marcador in rp.text:
                        pag_persist = pag
                        contexto, trecho = C.detetar_contexto(rp.text, marcador)
                        break
                if not pag_persist:
                    continue

                # Passo 2: payload de prova adequado ao contexto -> confirmar execução.
                token = C.novo_marcador("tok")
                payload = C.payload_prova(contexto, token)
                dados[nome] = payload
                self._pedir("POST", pe.url, dados)
                executou = None
                if self.conf:
                    executou = self.conf.confirmar_get(pag_persist, token)

                achados.append(Achado(
                    tipo="armazenado", url=pag_persist,
                    metodo=f"POST em {pe.url} → persiste em GET",
                    parametro=nome, contexto=contexto,
                    caracteres_livres=[], trecho=trecho.strip(),
                    payload_prova=payload, executou=executou,
                    nota_extra=f"Injetado via POST em {pe.url} (campo '{nome}'). "
                               f"Persistiu e é servido em {pag_persist} a todos "
                               f"os visitantes."))
                self._anunciar("armazenado", pag_persist, nome, contexto, executou)
        return achados

    # --------------------------------------------------------------------- DOM
    def dom(self, url):
        achados = []
        r = self._pedir("GET", url, {})
        if r is None:
            return achados
        soup = BeautifulSoup(r.text, "html.parser")
        codigo = "\n".join(s.get_text() for s in soup.find_all("script"))
        if not codigo.strip():
            return achados

        fontes = [f for f in FONTES_DOM if f in codigo]
        sumidouros = [s for s in SUMIDOUROS_DOM
                      if re.search(s, codigo)]
        if not (fontes and sumidouros):
            return achados

        # tentativa de confirmação via fragmento (#) com headless
        token = C.novo_marcador("tok")
        payload = C.payload_dom_sem_espacos(token)
        alvo = url + "#" + payload
        executou = None
        if self.conf:
            executou = self.conf.confirmar_get(alvo, token)

        trecho = "fontes: " + ", ".join(fontes) + " | sumidouros: " + \
                 ", ".join(s.replace("\\", "") for s in sumidouros)
        achados.append(Achado(
            tipo="dom", url=url, metodo="GET", parametro="(DOM via #fragmento)",
            contexto=C.JS_BLOCO, caracteres_livres=[], trecho=trecho,
            payload_prova=alvo,
            executou=executou,
            nota_extra="Dados controláveis pelo utilizador (" +
                       ", ".join(fontes) + ") chegam a um sumidouro perigoso (" +
                       ", ".join(s.replace('\\', '') for s in sumidouros) +
                       ") no JavaScript da página."))
        self._anunciar("dom", url, "(DOM)", C.JS_BLOCO, executou)
        return achados

    # ----------------------------------------------------------------- aux UI
    def _anunciar(self, tipo, url, param, contexto, executou):
        marca = {True: "EXECUÇÃO CONFIRMADA", False: "reflete (não executou)",
                 None: "potencial"}[executou]
        print(f"    [!] XSS {tipo}: {param}  [{contexto}]  -> {marca}")
