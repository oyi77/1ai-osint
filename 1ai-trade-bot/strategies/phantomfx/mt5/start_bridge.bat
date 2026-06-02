@echo off
REM PhantomFX Signal Bridge — Auto-start script
REM Letakkan di folder yang sama dengan phantomfx_signal_bridge.py

cd /d "%~dp0"
echo ===============================================
echo  PhantomFX Signal Bridge v4.1
echo  Starting on port 8765...
echo ===============================================
python phantomfx_signal_bridge.py --port 8765
pause
