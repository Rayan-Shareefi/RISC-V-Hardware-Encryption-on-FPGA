@echo off
rem ===========================================================================
rem run_system_sim.bat - simulate the whole FPGA design (CPU + crypto hardware)
rem running the C program that was last built with "make APP=crypto_hw_test clean exe image" in
rem neorv32-main\sw\example\demo_blink_led. The UART output (what Tera Term
rem would show) is saved to hw\sim_build_system\uart0.log.
rem Simulates 1000 ms of real time (enough for the whole self-test output); this takes several minutes.
rem ===========================================================================
setlocal
set VIVADO_BIN=D:\Graduation-Project\2025.2\Vivado\bin
set CORE=..\..\Projects\Simple-Code\Simple-Code.srcs\sources_1\imports\core
set APP=..\..\neorv32-main\sw\example\demo_blink_led
set SIMSRC=..\..\Projects\Simple-Code\Simple-Code.srcs\sim_1\imports\sim
cd /d "%~dp0"
if not exist sim_build_system mkdir sim_build_system
cd sim_build_system

rem "make ... image" writes sim_neorv32_imem_image.vhd and names its VHDL package after the file
rem (sim_neorv32_imem_image), but the IMEM ROM uses the package neorv32_imem_image. So compile a
rem copy with the package renamed (the Vivado-linked neorv32_imem_image.vhd is not touched).
powershell -NoProfile -Command "(Get-Content '%APP%\sim_neorv32_imem_image.vhd') -replace 'sim_neorv32_imem_image','neorv32_imem_image' | Set-Content -Encoding ascii imem_image_sim.vhd" || goto :fail

rem NEORV32 files in compile order (rtl\file_list_soc.f), our crypto file before the CFU
call "%VIVADO_BIN%\xvhdl.bat" --2008 -work neorv32 ^
  %CORE%\neorv32_package.vhd %CORE%\neorv32_sys.vhd %CORE%\neorv32_cpu_decompressor.vhd ^
  %CORE%\neorv32_cpu_frontend.vhd %CORE%\neorv32_cpu_control.vhd %CORE%\neorv32_cpu_hwtrig.vhd ^
  %CORE%\neorv32_prim.vhd %CORE%\neorv32_cpu_counters.vhd %CORE%\neorv32_cpu_regfile.vhd ^
  %CORE%\neorv32_cpu_alu_shifter.vhd %CORE%\neorv32_cpu_alu_muldiv.vhd %CORE%\neorv32_cpu_alu_bitmanip.vhd ^
  %CORE%\neorv32_cpu_alu_fpu.vhd ..\crypto_accel.vhd %CORE%\neorv32_cpu_alu_cfu.vhd ^
  %CORE%\neorv32_cpu_alu_cond.vhd %CORE%\neorv32_cpu_alu_crypto.vhd %CORE%\neorv32_cpu_alu.vhd ^
  %CORE%\neorv32_cpu_lsu.vhd %CORE%\neorv32_cpu_pmp.vhd %CORE%\neorv32_cpu_trace.vhd %CORE%\neorv32_cpu.vhd ^
  %CORE%\neorv32_cache.vhd %CORE%\neorv32_bus.vhd %CORE%\neorv32_dma.vhd %CORE%\neorv32_imem.vhd ^
  %CORE%\neorv32_dmem.vhd %CORE%\neorv32_xbus.vhd %CORE%\neorv32_bootrom.vhd %CORE%\neorv32_cfs.vhd ^
  %CORE%\neorv32_sdi.vhd %CORE%\neorv32_gpio.vhd %CORE%\neorv32_wdt.vhd %CORE%\neorv32_clint.vhd ^
  %CORE%\neorv32_uart.vhd %CORE%\neorv32_spi.vhd %CORE%\neorv32_twi.vhd %CORE%\neorv32_twd.vhd ^
  %CORE%\neorv32_pwm.vhd %CORE%\neorv32_trng.vhd %CORE%\neorv32_neoled.vhd %CORE%\neorv32_gptmr.vhd ^
  %CORE%\neorv32_onewire.vhd %CORE%\neorv32_slink.vhd %CORE%\neorv32_tracer.vhd %CORE%\neorv32_sysinfo.vhd ^
  %CORE%\neorv32_debug_dtm.vhd %CORE%\neorv32_debug_auth.vhd %CORE%\neorv32_debug_dm.vhd ^
  %CORE%\neorv32_top.vhd %CORE%\neorv32_cache_ram.vhd imem_image_sim.vhd ^
  %CORE%\neorv32_imem_rom.vhd %CORE%\neorv32_imem_ram.vhd %CORE%\neorv32_dmem_ram.vhd ^
  %CORE%\neorv32_bootrom_image.vhd %CORE%\neorv32_bootrom_rom.vhd ^
  ..\..\Projects\Simple-Code\Simple-Code.srcs\sources_1\imports\test_setups\neorv32_test_setup_approm.vhd ^
  || goto :fail
call "%VIVADO_BIN%\xvhdl.bat" --2008 %SIMSRC%\sim_uart_rx.vhd ..\tb_system.vhd || goto :fail
call "%VIVADO_BIN%\xelab.bat" tb_system -s sys_sim -L neorv32 || goto :fail
echo run 1000 ms > run.tcl
echo quit >> run.tcl
call "%VIVADO_BIN%\xsim.bat" sys_sim -tclbatch run.tcl > xsim_console.txt || goto :fail
echo.
echo ===== UART output (uart0.log) =====
type uart0.log
goto :end

:fail
echo.
echo *** SIMULATION FAILED TO COMPILE OR RUN - see messages above ***

:end
if not "%1"=="nopause" pause
