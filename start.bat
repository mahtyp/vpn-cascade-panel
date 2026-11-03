@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PY="
rem Ищем настоящий Python. Заглушка Microsoft Store (WindowsApps\python.exe) проверку не пройдёт.
py -3 -c "import sys" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys" >nul 2>nul && set "PY=python"
if not defined PY python3 -c "import sys" >nul 2>nul && set "PY=python3"
if not defined PY for /d %%D in ("%LocalAppData%\Programs\Python\Python3*") do if exist "%%D\python.exe" set PY="%%D\python.exe"
if not defined PY for /d %%D in ("%ProgramFiles%\Python3*") do if exist "%%D\python.exe" set PY="%%D\python.exe"
if not defined PY for /d %%D in ("C:\Python3*") do if exist "%%D\python.exe" set PY="%%D\python.exe"
if not defined PY goto nopython
echo Python: %PY%
%PY% --version
rem Если панель скачана из GitHub (git clone) — подтянуть свежую версию.
if exist ".git" (
  where git >nul 2>nul && (
    echo Проверяю обновления панели...
    git pull --ff-only --quiet || echo Не удалось обновить из GitHub — запускаю текущую версию.
  )
)
echo Проверяю библиотеки...
%PY% -m pip install --disable-pip-version-check --no-warn-script-location -q -r requirements.txt
if errorlevel 1 goto nopip
if /i "%~1"=="console" goto console
rem Панель уходит в трей (значок у часов), это окно закроется само.
%PY% dash.py --launch
if errorlevel 1 goto failed
timeout /t 4 >nul
exit /b 0

:console
rem Режим с окном консоли, как раньше: start.bat console
%PY% dash.py
pause
exit /b 0

:failed
echo.
echo Панель не запустилась (сообщение выше). Пришлите скриншот этого окна.
pause
exit /b 1

:nopython
echo.
echo Не нашёл установленный Python.
echo Поставьте его с https://www.python.org/downloads/ и в первом окне установщика
echo отметьте галочку "Add python.exe to PATH". Потом запустите start.bat снова.
pause
exit /b 1

:nopip
echo.
echo Не удалось поставить библиотеки (сообщение выше).
echo Пришлите скриншот этого окна.
pause
exit /b 1
