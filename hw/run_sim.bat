@echo off
rem ===========================================================================
rem run_sim.bat - compile and run tb_crypto_accel in Vivado's simulator (xsim)
rem Double-click it, or run it from a terminal. Results print at the end.
rem Build files go to hw\sim_build\ (safe to delete).
rem To see waveforms instead: run it once, then in sim_build run
rem   "D:\Graduation-Project\2025.2\Vivado\bin\xsim.bat" tb_sim -gui
rem ===========================================================================
setlocal
set VIVADO_BIN=D:\Graduation-Project\2025.2\Vivado\bin
cd /d "%~dp0"
if not exist sim_build mkdir sim_build
cd sim_build

call "%VIVADO_BIN%\xvhdl.bat" --2008 ..\crypto_accel.vhd ..\tb_poly1305_vectors_pkg.vhd ..\tb_keccak_vectors_pkg.vhd ..\tb_crypto_accel.vhd || goto :fail
call "%VIVADO_BIN%\xelab.bat" tb_crypto_accel -s tb_sim -debug typical || goto :fail
call "%VIVADO_BIN%\xsim.bat" tb_sim -R || goto :fail
goto :end

:fail
echo.
echo *** SIMULATION FAILED TO COMPILE OR RUN - see messages above ***

:end
if not "%1"=="nopause" pause
