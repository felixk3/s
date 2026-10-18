# -*- coding: utf-8 -*-
"""
Cálculo de severidade de cada achado de XSS.

Modelo transparente e defensável (inspirado no raciocínio do CVSS, simplificado
para XSS). O que mais pesa: a falha executa mesmo? E o cookie de sessão fica
exposto por falta de HttpOnly?
"""

from . import contextos as ctx


# Peso base por tipo de XSS
_BASE_TIPO = {
    "armazenado": 8.0,   # afeta todos os utilizadores, persistente
    "refletido": 6.0,
    "dom": 6.0,
}

# Contextos que facilitam execução direta sobem ligeiramente
_AJUSTE_CTX = {
    ctx.JS_BLOCO: +1.0,
    ctx.ATTR_URL: +0.5,
    ctx.CORPO_HTML: +0.5,
}


def classificar(achado, sessao_exposta=False):
    """
    Devolve (severidade, pontuacao 0-10).
    - achado: modelo.Achado
    - sessao_exposta: True se existe cookie de sessão sem HttpOnly.
    """
    p = _BASE_TIPO.get(achado.tipo, 6.0)
    p += _AJUSTE_CTX.get(achado.contexto, 0.0)

    if achado.executou is True:
        p += 1.5                      # confirmado a executar: risco real
    elif achado.executou is False:
        p -= 2.5                      # reflete mas não executou no navegador
    # None (não confirmado) não altera

    if sessao_exposta:
        p += 1.0                      # XSS + cookie legível = roubo de sessão

    p = max(0.0, min(10.0, round(p, 1)))

    if p >= 9.0:
        sev = "Crítica"
    elif p >= 7.0:
        sev = "Alta"
    elif p >= 4.0:
        sev = "Média"
    elif p > 0.0:
        sev = "Baixa"
    else:
        sev = "Informativa"
    return sev, p


ORDEM = {"Crítica": 0, "Alta": 1, "Média": 2, "Baixa": 3, "Informativa": 4}


def ordenar(achados):
    return sorted(achados, key=lambda a: (ORDEM.get(a.severidade, 9),
                                          -a.pontuacao))
