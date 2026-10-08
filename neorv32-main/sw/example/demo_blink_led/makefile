# Application makefile.
# Use this makefile to configure all relevant CPU / compiler options.

# Override the default CPU ISA
MARCH = rv32imc_zicsr_zifencei

# Override the default RISC-V GCC prefix
#RISCV_PREFIX ?= riscv-none-elf-

# Override default optimization goal
EFFORT = -O2

# Add extended debug symbols
USER_FLAGS += -ggdb -gdwarf-3

# Adjust processor IMEM size (32 KB since Step C, must match IMEM_SIZE in the Vivado top file)
USER_FLAGS += -Wl,--defsym,__neorv32_rom_size=32k

# Adjust processor DMEM size: the FPGA has 128 KB data memory (for file_crypto); the other
# programs keep linking for 8 KB, so their binaries stay exactly as before (see APP below)

# Adjust maximum heap size
#USER_FLAGS += -Wl,--defsym,__neorv32_heap_size=1k

# Program to build (each program has its own main()): choose it with APP, then send the
# resulting neorv32_exe.bin to the board with Tera Term (bootloader: u, send file binary, e).
#   make APP=my_crypto clean exe                -> my_crypto.c (your own message / key / nonce)
#   make APP=demo_chacha20 clean exe            -> demo_chacha20.c
#   make APP=demo_chacha20_poly1305 clean exe   -> demo_chacha20_poly1305.c
#   make APP=demo_keccak clean exe              -> demo_keccak.c
#   make APP=crypto_hw_test clean exe           -> crypto_hw_test.c (self-test of all units)
#   make APP=file_crypto clean exe              -> file_crypto.c (encrypt / decrypt a picture or file)
# Older per-phase benchmarks: chacha20_bench (default), poly1305_bench, keccak_bench,
# chacha20_poly1305_bench. For the full-CPU simulation add "image":
#   make APP=crypto_hw_test clean exe image     -> also writes sim_neorv32_imem_image.vhd
APP ?= chacha20_bench
ifeq ($(APP),file_crypto)
USER_FLAGS += -Wl,--defsym,__neorv32_ram_size=128k
else
USER_FLAGS += -Wl,--defsym,__neorv32_ram_size=8k
endif
APP_SRC = $(APP).c chacha20_sw.c poly1305_sw.c keccak_sw.c

# "make image" writes the program image for the full-CPU simulation (hw\run_system_sim.bat)
# to this file. The Vivado project uses neorv32_imem_image.vhd (its content does not matter
# for the bitstream, the FPGA boots the bootloader), so "make clean" never deletes that one.
APP_VHD = sim_neorv32_imem_image.vhd

# Set path to NEORV32 root directory
NEORV32_HOME ?= ../../..

# Include the main NEORV32 makefile
include $(NEORV32_HOME)/sw/common/common.mk
