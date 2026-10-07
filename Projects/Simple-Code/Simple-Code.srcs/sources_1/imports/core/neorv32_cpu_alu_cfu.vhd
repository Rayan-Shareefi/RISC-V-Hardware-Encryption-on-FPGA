-- ================================================================================ --
-- NEORV32 CPU - ALU Custom (RISC-V Instructions) Functions Unit (CFU)              --
-- -------------------------------------------------------------------------------- --
-- Graduation project version: custom crypto instructions.                          --
-- Replaces the original XTEA example. This file only decodes the instructions;     --
-- all crypto logic is in hw/crypto_accel.vhd (entity crypto_accel).                --
--                                                                                  --
-- All instructions use the RISC-V CUSTOM-0 opcode, R-type, funct7 = 0:             --
--   funct3 = 000  chacha.start            start ChaCha20 on the loaded block       --
--   funct3 = 001  crypto.write rs1, rs2   register[rs1] = rs2                      --
--   funct3 = 010  crypto.read  rd, rs1    rd = register[rs1]                       --
--                                         (CPU waits here until the result is ready) --
--   funct3 = 011  poly.start              start Poly1305 on the loaded message     --
--   funct3 = 100  keccak.start            start SHA3-256 on the loaded message     --
-- Any other funct3/funct7 -> illegal instruction exception.                        --
-- Register map: see crypto_accel in hw/crypto_accel.vhd.                           --
-- C macros: crypto_accel.h in the application folder.                              --
-- -------------------------------------------------------------------------------- --
-- The NEORV32 RISC-V Processor - https://github.com/stnolting/neorv32              --
-- Copyright (c) NEORV32 contributors.                                              --
-- Copyright (c) 2020 - 2026 Stephan Nolting. All rights reserved.                  --
-- Licensed under the BSD-3-Clause license, see LICENSE for details.                --
-- SPDX-License-Identifier: BSD-3-Clause                                            --
-- ================================================================================ --

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library neorv32;
use neorv32.neorv32_package.all;

entity neorv32_cpu_alu_cfu is
  port (
    -- global control --
    clk_i    : in  std_ulogic; -- global clock, rising edge
    rstn_i   : in  std_ulogic; -- global reset, low-active, async
    -- request --
    start_i  : in  std_ulogic; -- start trigger, single-shot
    inst_i   : in  std_ulogic_vector(31 downto 0); -- full instruction word
    rs1_i    : in  std_ulogic_vector(31 downto 0); -- register source operand 1
    rs2_i    : in  std_ulogic_vector(31 downto 0); -- register source operand 2
    -- response --
    result_o : out std_ulogic_vector(31 downto 0); -- operation result
    valid_o  : out std_ulogic                      -- operation done; result valid
  );
end neorv32_cpu_alu_cfu;

architecture neorv32_cpu_alu_cfu_rtl of neorv32_cpu_alu_cfu is

  constant opcode_custom0_c : std_ulogic_vector(6 downto 0) := "0001011"; -- CUSTOM-0 opcode

  -- instruction identifiers (funct3 bit-field) --
  constant op_chacha_start_c : std_ulogic_vector(2 downto 0) := "000";
  constant op_write_c        : std_ulogic_vector(2 downto 0) := "001";
  constant op_read_c         : std_ulogic_vector(2 downto 0) := "010";
  constant op_poly_start_c   : std_ulogic_vector(2 downto 0) := "011";
  constant op_keccak_start_c : std_ulogic_vector(2 downto 0) := "100";

  -- instruction decoder --
  signal is_crypto : std_ulogic; -- CUSTOM-0 opcode with funct7 = 0
  signal funct3    : std_ulogic_vector(2 downto 0);

  -- accelerator interface --
  signal acc_we, acc_start : std_logic;
  signal acc_start_poly     : std_logic;
  signal acc_start_keccak   : std_logic;
  signal raddr_buf         : std_ulogic_vector(7 downto 0); -- read address, kept while the CPU waits
  signal acc_raddr         : std_logic_vector(7 downto 0);
  signal acc_rdata         : std_logic_vector(31 downto 0);
  signal acc_rvalid        : std_logic;
  signal acc_busy          : std_logic;

begin

  -- Instruction Decode ---------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  is_crypto <= '1' when (inst_i(6 downto 0) = opcode_custom0_c) and (inst_i(31 downto 25) = "0000000") else '0';
  funct3    <= inst_i(14 downto 12);

  acc_start <= '1' when (start_i = '1') and (is_crypto = '1') and (funct3 = op_chacha_start_c) else '0';
  acc_we    <= '1' when (start_i = '1') and (is_crypto = '1') and (funct3 = op_write_c) else '0';
  acc_start_poly <= '1' when (start_i = '1') and (is_crypto = '1') and (funct3 = op_poly_start_c) else '0';
  acc_start_keccak <= '1' when (start_i = '1') and (is_crypto = '1') and (funct3 = op_keccak_start_c) else '0';

  -- read address: rs1 in the first cycle, then the buffered copy while the CPU waits --
  raddr_buffer: process(rstn_i, clk_i)
  begin
    if (rstn_i = '0') then
      raddr_buf <= (others => '0');
    elsif rising_edge(clk_i) then
      if (start_i = '1') then
        raddr_buf <= rs1_i(7 downto 0);
      end if;
    end if;
  end process raddr_buffer;

  acc_raddr <= std_logic_vector(rs1_i(7 downto 0)) when (start_i = '1') else std_logic_vector(raddr_buf);


  -- Crypto Accelerator (hw/crypto_accel.vhd) -----------------------------------------------
  -- -------------------------------------------------------------------------------------------
  crypto_accel_inst: entity neorv32.crypto_accel
  port map (
    clk          => std_logic(clk_i),
    rstn         => std_logic(rstn_i),
    we           => acc_we,
    waddr        => std_logic_vector(rs1_i(7 downto 0)),
    wdata        => std_logic_vector(rs2_i),
    raddr        => acc_raddr,
    rdata        => acc_rdata,
    rvalid       => acc_rvalid,
    start_chacha => acc_start,
    start_poly   => acc_start_poly,
    start_keccak => acc_start_keccak,
    busy         => acc_busy
  );


  -- Function Result Select -----------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  result_select: process(is_crypto, funct3, acc_rdata, acc_rvalid)
  begin -- no register stage needed; the CFU output is registered inside the ALU module
    result_o <= (others => '0');
    valid_o  <= '0'; -- default: not a valid instruction -> illegal instruction exception
    if (is_crypto = '1') then
      case funct3 is
        when op_chacha_start_c | op_write_c | op_poly_start_c | op_keccak_start_c => -- single cycle
          valid_o <= '1';
        when op_read_c => -- wait until the result is ready
          result_o <= std_ulogic_vector(acc_rdata);
          valid_o  <= std_ulogic(acc_rvalid);
        when others =>
          null;
      end case;
    end if;
  end process result_select;

end neorv32_cpu_alu_cfu_rtl;
