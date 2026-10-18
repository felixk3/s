# -*- coding: utf-8 -*-
"""
Confirmação de execução real com navegador headless (Playwright).

É o que separa um scanner sério de um que "adivinha": em vez de assumir que a
reflexão é explorável, abre a página num navegador real e verifica se o payload
INOFENSIVO realmente executou (definiu window[token] e chamou console.log).
Assim o relatório não tem falsos positivos.

Se o Playwright não estiver instalado, a ferramenta continua a funcionar em
modo "só análise de contexto" (menos preciso) e avisa.
"""

import json
from urllib.parse import urlencode

_DISPONIVEL = None


def disponivel():
    global _DISPONIVEL
    if _DISPONIVEL is None:
        try:
            from playwright.sync_api import sync_playwright  # noqa
            _DISPONIVEL = True
        except Exception:
            _DISPONIVEL = False
    return _DISPONIVEL


class Confirmador:
    """Gere um navegador headless reutilizável para confirmar execução."""

    def __init__(self, cookies=None, cabecalhos=None, tempo_limite=8):
        self.cookies = cookies or {}
        self.cabecalhos = cabecalhos or {}
        self.tempo_limite = tempo_limite * 1000
        self._pw = None
        self._browser = None

    def __enter__(self):
        if not disponivel():
            return self
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        return self

    def __exit__(self, *a):
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    def _nova_pagina(self, url_base):
        ctx = self._browser.new_context(ignore_https_errors=True)
        if self.cabecalhos:
            ctx.set_extra_http_headers(self.cabecalhos)
        if self.cookies:
            from urllib.parse import urlparse
            dominio = urlparse(url_base).hostname
            ctx.add_cookies([
                {"name": k, "value": v, "domain": dominio, "path": "/"}
                for k, v in self.cookies.items()
            ])
        pg = ctx.new_page()
        return ctx, pg

    def confirmar_get(self, url, token):
        """Abre url (GET) e verifica se window[token] foi definido."""
        if not self._browser:
            return None
        return self._executar(url, token, metodo="GET")

    def confirmar_post(self, url, dados, token):
        if not self._browser:
            return None
        return self._executar(url, token, metodo="POST", dados=dados)

    def confirmar_html(self, html, token, url_base="http://127.0.0.1/"):
        """Confirma execução a partir de HTML directo (para XSS armazenado/DOM)."""
        if not self._browser:
            return None
        ctx, pg = self._nova_pagina(url_base)
        try:
            achou = {"v": False, "erros": []}
            pg.on("console", lambda m: None)
            pg.set_content(html, timeout=self.tempo_limite)
            pg.wait_for_timeout(250)
            achou["v"] = bool(pg.evaluate(f"() => window['{token}'] === 1"))
            return achou["v"]
        except Exception:
            return False
        finally:
            ctx.close()

    def _executar(self, url, token, metodo="GET", dados=None):
        ctx, pg = self._nova_pagina(url)
        disparou = {"v": False}

        def _msg(m):
            try:
                if token in (m.text or ""):
                    disparou["v"] = True
            except Exception:
                pass

        pg.on("console", _msg)
        # Diálogos (alert/confirm) também contam como execução.
        pg.on("dialog", lambda d: (disparou.__setitem__("v", True), d.dismiss()))
        try:
            if metodo == "GET":
                pg.goto(url, timeout=self.tempo_limite, wait_until="load")
            else:
                # POST via formulário sintético
                campos = "".join(
                    f'<input name="{k}" value="">' for k in dados
                )
                form = f'<form id="f" method="POST" action="{url}">{campos}</form>'
                ctx2, pg2 = ctx, pg
                pg.set_content(form, timeout=self.tempo_limite)
                for k, v in dados.items():
                    pg.eval_on_selector(
                        f'input[name="{k}"]',
                        "(el, val) => el.value = val", v)
                pg.eval_on_selector("#f", "f => f.submit()")
                pg.wait_for_load_state("load", timeout=self.tempo_limite)
            # dar uma margem para onerror/async
            pg.wait_for_timeout(250)
            if not disparou["v"]:
                try:
                    disparou["v"] = bool(
                        pg.evaluate(f"() => window['{token}'] === 1"))
                except Exception:
                    pass
            return disparou["v"]
        except Exception:
            return disparou["v"]
        finally:
            ctx.close()
