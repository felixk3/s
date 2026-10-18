# -*- coding: utf-8 -*-
"""Estruturas de dados partilhadas."""

import dataclasses
import datetime
from typing import List, Optional, Dict


@dataclasses.dataclass
class PontoEntrada:
    metodo: str                 # GET / POST
    url: str                    # endpoint
    parametros: Dict[str, str]  # nome -> valor base
    origem: str = ""            # onde foi descoberto (URL/formulário)


@dataclasses.dataclass
class Achado:
    tipo: str                   # refletido / armazenado / dom
    url: str
    metodo: str
    parametro: str
    contexto: str
    caracteres_livres: List[str]
    trecho: str
    payload_prova: str
    executou: Optional[bool]    # True/False (headless) ou None (não confirmado)
    severidade: str = ""        # Crítica/Alta/Média/Baixa/Informativa
    pontuacao: float = 0.0
    nota_extra: str = ""
    momento: str = dataclasses.field(
        default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds"))


@dataclasses.dataclass
class AchadoCookie:
    nome: str
    httponly: bool
    secure: bool
    samesite: str
    problemas: List[str]
    severidade: str = ""


@dataclasses.dataclass
class Relatorio:
    alvo: str
    inicio: str
    fim: str = ""
    pontos_testados: int = 0
    achados: List[Achado] = dataclasses.field(default_factory=list)
    cookies: List[AchadoCookie] = dataclasses.field(default_factory=list)
    headless: bool = False
    avisos: List[str] = dataclasses.field(default_factory=list)
