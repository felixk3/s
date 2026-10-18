# -*- coding: utf-8 -*-
"""
Auditoria de segurança de cookies.

Mostra ao developer, com precisão, se um XSS conseguiria roubar a sessão. Não
rouba nada: apenas lê os atributos de segurança que o próprio servidor definiu.
"""

import re
from .modelo import AchadoCookie


# nomes comuns de cookies de sessão (para elevar a severidade)
NOMES_SESSAO = re.compile(
    r"(sess|session|sid|auth|token|jwt|phpsessid|jsessionid|asp\.net)",
    re.IGNORECASE)


def auditar(resposta):
    """Analisa os cabeçalhos Set-Cookie da resposta."""
    achados = []
    # requests junta múltiplos Set-Cookie; usamos raw quando possível
    brutos = _set_cookie_brutos(resposta)
    for linha in brutos:
        achados.append(_analisar_um(linha))
    return achados


def _set_cookie_brutos(resposta):
    linhas = []
    # urllib3 expõe os cabeçalhos repetidos
    try:
        raw = resposta.raw.headers
        linhas = raw.get_all("Set-Cookie") or []
    except Exception:
        pass
    if not linhas:
        sc = resposta.headers.get("Set-Cookie")
        if sc:
            # separar cuidadosamente (datas têm vírgulas)
            linhas = re.split(r",(?=[^ ;]+=)", sc)
    return linhas


def _analisar_um(linha):
    nome = linha.split("=", 1)[0].strip()
    baixo = linha.lower()
    httponly = "httponly" in baixo
    secure = "secure" in baixo
    m = re.search(r"samesite\s*=\s*(\w+)", baixo)
    samesite = m.group(1).capitalize() if m else "(ausente)"

    problemas = []
    sessao = bool(NOMES_SESSAO.search(nome))
    if not httponly:
        problemas.append(
            "Sem HttpOnly: JavaScript (logo, um XSS) consegue ler este cookie "
            "via document.cookie.")
    if not secure:
        problemas.append(
            "Sem Secure: o cookie pode viajar em HTTP não cifrado e ser "
            "intercetado na rede.")
    if samesite in ("(ausente)", "None"):
        problemas.append(
            f"SameSite={samesite}: reduz a proteção contra CSRF e vazamento "
            "entre sítios.")

    sev = "Informativa"
    if problemas:
        if sessao and not httponly:
            sev = "Alta"      # cookie de sessão legível por XSS
        elif not httponly:
            sev = "Média"
        else:
            sev = "Baixa"

    return AchadoCookie(
        nome=nome, httponly=httponly, secure=secure,
        samesite=samesite, problemas=problemas, severidade=sev)


REMEDIACAO_COOKIE = (
    "Defina os cookies de sessão com os atributos de segurança: "
    "HttpOnly (impede leitura por JavaScript), Secure (só envia por HTTPS) e "
    "SameSite=Strict ou Lax (limita envio entre sítios). Exemplo: "
    "Set-Cookie: SESSION=...; HttpOnly; Secure; SameSite=Strict; Path=/")
