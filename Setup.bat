@echo off
Powershell.exe -NoProfile -Command "& {Start-Process Powershell.exe -Argumentlist '-NoProfile -ExecutionPolicy Bypass -File "%~dp0\Install-Python.ps1"' -Verb RunAs}
echo Once Python is Finished Press Any Key.
pause > nul
pip install pypiwin32