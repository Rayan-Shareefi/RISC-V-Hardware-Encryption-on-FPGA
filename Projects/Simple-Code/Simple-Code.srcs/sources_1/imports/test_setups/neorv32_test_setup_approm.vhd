-- ============================================================================
-- neorv32_test_setup_approm.vhd - FPGA top level (Digilent Cmod A7-35T, 12 MHz)
--
-- NEORV32 RISC-V CPU (rv32imc) with:
--   - CFU: custom crypto instructions -> hw/crypto_accel.vhd (ChaCha20, ...)
--   - CFS: 1 microsecond counter for time measurement
--   - UART0 (19200 baud, set in software), 8 GPIO outputs (LEDs)
-- BOOT_MODE 0 (FPGA): the NEORV32 bootloader starts; upload the program
--   (neorv32_exe.bin) over UART with Tera Term or hw/upload.ps1.
-- BOOT_MODE 2 (simulation, hw/tb_system.vhd): the program is preloaded in the
--   IMEM from neorv32_imem_image.vhd ("make image").
-- ============================================================================
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library neorv32;
use neorv32.neorv32_package.all;

entity neorv32_test_setup_approm is
  generic (
    CLOCK_FREQUENCY : natural := 12000000;
    BOOT_MODE       : natural := 0;          -- 0 = bootloader (FPGA), 2 = IMEM image (simulation)
    IMEM_SIZE       : natural := 32*1024;    -- 32 KB (was 16 KB) for the ChaCha20-Poly1305 programs
    DMEM_SIZE       : natural := 8*1024
  );
  port (
    clk_i       : in  std_ulogic;
    rstn_i      : in  std_ulogic; -- BTN0: high while pressed (inverted below)
    uart0_txd_o : out std_ulogic;
    uart0_rxd_i : in  std_ulogic;
    gpio_o      : out std_ulogic_vector(7 downto 0)
  );
end entity;

architecture neorv32_test_setup_approm_rtl of neorv32_test_setup_approm is

  signal con_gpio_out : std_ulogic_vector(31 downto 0);
  signal rstn_inv     : std_ulogic; -- low-active system reset

begin

  -- the Cmod A7 button is high-active, the CPU reset is low-active --
  rstn_inv <= not rstn_i;

  -- CPU Instance --
  neorv32_top_inst: entity neorv32.neorv32_top
  generic map (
    CLOCK_FREQUENCY  => CLOCK_FREQUENCY,
    BOOT_MODE_SELECT => BOOT_MODE,      -- see header
    RISCV_ISA_C      => true,           -- compressed instructions
    RISCV_ISA_M      => true,           -- hardware multiply/divide
    RISCV_ISA_Zicntr => true,           -- cycle counter
    RISCV_ISA_Xcfu   => true,           -- custom crypto instructions (CFU)
    IMEM_EN          => true,
    IMEM_SIZE        => IMEM_SIZE,
    DMEM_EN          => true,
    DMEM_SIZE        => DMEM_SIZE,
    IO_GPIO_NUM      => 8,
    IO_CLINT_EN      => true,
    IO_UART0_EN      => true,
    IO_CFS_EN        => true,           -- 1 microsecond counter (CFS)
    XBUS_EN          => false           -- no external bus devices
  )
  port map (
    clk_i       => clk_i,
    rstn_i      => rstn_inv,
    uart0_txd_o => uart0_txd_o,
    uart0_rxd_i => uart0_rxd_i,
    gpio_o      => con_gpio_out
  );

  gpio_o <= con_gpio_out(7 downto 0);

end architecture;
