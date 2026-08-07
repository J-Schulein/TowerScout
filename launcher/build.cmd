@echo off
setlocal
python -m PyInstaller --clean --noconfirm "%~dp0TowerScoutLauncher.spec"
if errorlevel 1 exit /b %ERRORLEVEL%
python "%~dp0build_provenance.py" --build-dir "dist/TowerScoutLauncher"
exit /b %ERRORLEVEL%
