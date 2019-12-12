@echo off
Powershell.exe -NoProfile -Command "& {Start-Process Powershell.exe -Argumentlist '-NoProfile -ExecutionPolicy Bypass -File "%~dp0\Install-Python.ps1"' -Verb RunAs}
timeout 90
pip install https://github.com/pyinstaller/pyinstaller/tarball/develop
pip install pypiwin32