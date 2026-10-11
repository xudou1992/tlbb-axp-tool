@echo off
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo [错误] 没有找到 python，请先安装 Python 3.13 并勾选 Add python.exe to PATH，
  echo        或编辑本文件，把 python 换成解释器的完整路径。
  pause
  exit /b 1
)
start "" python server.py
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:5000"
