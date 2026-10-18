#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Laboratório LOCAL vulnerável, só para validar o Khoza Sec XSS. Não usar em produção."""
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

GUESTBOOK = []  # XSS armazenado

HOME = """<!doctype html><html><head><title>Lab</title></head><body>
<h1>Home</h1>
<a href="/busca?q=1">busca</a> <a href="/perfil?nome=x">perfil</a>
<a href="/js?nome=x">js</a> <a href="/dom">dom</a> <a href="/mural">mural</a>
</body></html>"""

def busca(q):  # refletido no corpo HTML (vulneravel) + seguro
    return f"""<!doctype html><html><body><h1>Busca</h1>
<p>Resultado: {q.get('q',[''])[0]}</p>
<p>Seguro: {html.escape(q.get('seguro',[''])[0])}</p>
<form method="GET" action="/busca"><input name="q"><input name="seguro"></form>
</body></html>"""

def perfil(q):  # refletido em atributo com aspas duplas (vulneravel)
    return f"""<!doctype html><html><body><h1>Perfil</h1>
<input type="text" value="{q.get('nome',[''])[0]}">
<form method="GET" action="/perfil"><input name="nome"></form>
</body></html>"""

def js(q):  # refletido dentro de string JS com aspas simples (vulneravel)
    return f"""<!doctype html><html><body><h1>JS</h1>
<script> var nome = '{q.get('nome',[''])[0]}'; console.log(nome); </script>
<form method="GET" action="/js"><input name="nome"></form>
</body></html>"""

DOM = """<!doctype html><html><body><h1>DOM</h1>
<div id="saida"></div>
<script>
  var dados = decodeURIComponent(location.hash.substring(1));
  document.getElementById('saida').innerHTML = dados;  // sumidouro perigoso
</script></body></html>"""

def mural_html():
    itens = "".join(f"<li>{m}</li>" for m in GUESTBOOK)  # armazenado (sem escape)
    return f"""<!doctype html><html><body><h1>Mural</h1>
<ul>{itens}</ul>
<form method="POST" action="/mural"><input name="mensagem"><input type="submit"></form>
</body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, corpo, set_cookie=True):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if set_cookie:
            # cookie de sessao SEM HttpOnly/Secure/SameSite (inseguro de proposito)
            self.send_header("Set-Cookie", "PHPSESSID=abc123xyz; Path=/")
        self.end_headers()
        self.wfile.write(corpo.encode())
    def do_GET(self):
        p = urlparse(self.path); q = parse_qs(p.query)
        rota = p.path
        if rota == "/": self._send(HOME)
        elif rota == "/busca": self._send(busca(q))
        elif rota == "/perfil": self._send(perfil(q))
        elif rota == "/js": self._send(js(q))
        elif rota == "/dom": self._send(DOM)
        elif rota == "/mural": self._send(mural_html())
        else: self._send("<h1>404</h1>")
    def do_POST(self):
        p = urlparse(self.path)
        n = int(self.headers.get("Content-Length", 0))
        corpo = self.rfile.read(n).decode()
        dados = parse_qs(corpo)
        if p.path == "/mural":
            GUESTBOOK.append(dados.get("mensagem", [""])[0])
            self._send(mural_html())
        else:
            self._send("<h1>ok</h1>")

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8099), H).serve_forever()
