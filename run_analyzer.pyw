#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Точка входа для запуска GUI двойным кликом (без окна консоли на Windows).

Расширение .pyw заставляет Windows запускать программу через pythonw.exe,
поэтому чёрное окно консоли не появляется.
"""

import os
import sys

# Гарантируем, что пакет bsod_analyzer доступен, где бы ни лежал этот файл.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bsod_analyzer.gui import main

if __name__ == "__main__":
    main()
