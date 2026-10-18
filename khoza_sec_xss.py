#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Khoza Sec XSS — lançador.

Scanner profissional de XSS (refletido, armazenado e DOM) com confirmação de
execução por navegador headless e auditoria de cookies. Uso exclusivo em
sistemas autorizados.

Equivalente a:  python3 -m khozaxss
"""
import sys

try:
    from khozaxss.cli import main
except ImportError:
    print("Coloque este ficheiro na pasta que contém o diretório 'khozaxss/'.")
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())
