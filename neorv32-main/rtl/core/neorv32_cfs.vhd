-- ================================================================================ --
-- NEORV32 SoC - Custom Functions Subsystem (CFS)                                   --
-- -------------------------------------------------------------------------------- --
-- Graduation project version: 1 microsecond counter for SW vs HW time measurement. --
--                                                                                  --
-- Register map (CFS base address 0xFFEB0000, in C: NEORV32_CFS->REG[n]):           --
--   REG[0]  R : microseconds counted since reset (32-bit, wraps after ~71 minutes) --
--           W : set the counter to the written value (write 0 to clear it)         --
--   REG[1]  R/W : clock cycles per microsecond (reset value 12 = 12 MHz clock)     --
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

entity neorv32_cfs is
  port (
    clk_i     : in  std_ulogic; -- global clock line
    rstn_i    : in  std_ulogic; -- global reset line, low-active, async
    bus_req_i : in  bus_req_t;  -- bus request
    bus_rsp_o : out bus_rsp_t;  -- bus response
    irq_o     : out std_ulogic; -- interrupt request
    cfs_in_i  : in  std_ulogic_vector(255 downto 0); -- custom inputs conduit
    cfs_out_o : out std_ulogic_vector(255 downto 0)  -- custom outputs conduit
  );
end neorv32_cfs;

architecture neorv32_cfs_rtl of neorv32_cfs is

  constant cycles_per_us_c : natural := 12; -- reset value: 12 MHz board clock

  signal per_us   : unsigned(15 downto 0); -- clock cycles per microsecond (REG[1])
  signal presc    : unsigned(15 downto 0); -- counts clock cycles inside one microsecond
  signal us_cnt   : unsigned(31 downto 0); -- microsecond counter (REG[0])
  signal rsp_ack  : std_ulogic;
  signal rsp_data : std_ulogic_vector(31 downto 0);

begin

  -- Microsecond Counter + Bus Access -------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  us_counter: process(rstn_i, clk_i)
  begin
    if (rstn_i = '0') then
      per_us   <= to_unsigned(cycles_per_us_c, 16);
      presc    <= (others => '0');
      us_cnt   <= (others => '0');
      rsp_ack  <= '0';
      rsp_data <= (others => '0');
    elsif rising_edge(clk_i) then
      -- count one microsecond every per_us clock cycles --
      if (presc >= per_us - 1) then
        presc  <= (others => '0');
        us_cnt <= us_cnt + 1;
      else
        presc <= presc + 1;
      end if;

      -- bus access: acknowledge every request one cycle later --
      rsp_ack  <= bus_req_i.stb;
      rsp_data <= (others => '0');
      if (bus_req_i.stb = '1') then
        if (bus_req_i.rw = '1') then -- write
          case bus_req_i.addr(3 downto 2) is
            when "00" => -- REG[0]: set counter
              us_cnt <= unsigned(bus_req_i.data);
              presc  <= (others => '0');
            when "01" => -- REG[1]: clock cycles per microsecond
              per_us <= unsigned(bus_req_i.data(15 downto 0));
            when others =>
              null;
          end case;
        else -- read
          case bus_req_i.addr(3 downto 2) is
            when "00"   => rsp_data <= std_ulogic_vector(us_cnt);
            when "01"   => rsp_data <= x"0000" & std_ulogic_vector(per_us);
            when others => rsp_data <= (others => '0');
          end case;
        end if;
      end if;
    end if;
  end process us_counter;

  bus_rsp_o.ack  <= rsp_ack;
  bus_rsp_o.err  <= '0';
  bus_rsp_o.data <= rsp_data;

  irq_o     <= '0'; -- no interrupt
  cfs_out_o <= (others => '0'); -- not used

end neorv32_cfs_rtl;
