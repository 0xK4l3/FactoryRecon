@echo off
title FactoryRecon - Modo Administrador (Escaneo Capa 2 Multi-Subred)
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process pythonw -ArgumentList '\"%~dp0app.py\"' -Verb RunAs"

