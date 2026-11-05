@echo off
title FactoryRecon - Escaner Ethernet
cd /d "%~dp0"
start "" pythonw app.py
if errorlevel 1 (
    python app.py
)

