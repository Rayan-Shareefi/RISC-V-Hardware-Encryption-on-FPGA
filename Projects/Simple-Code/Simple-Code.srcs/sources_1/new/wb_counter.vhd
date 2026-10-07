library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity wb_counter is
  port (
    clk_i     : in  std_ulogic;
    rstn_i    : in  std_ulogic;
    wb_cyc_i  : in  std_ulogic;
    wb_stb_i  : in  std_ulogic;
    wb_we_i   : in  std_ulogic;
    wb_adr_i  : in  std_ulogic_vector(31 downto 0);
    wb_dat_i  : in  std_ulogic_vector(31 downto 0);
    wb_dat_o  : out std_ulogic_vector(31 downto 0);
    wb_ack_o  : out std_ulogic
  );
end wb_counter;

architecture rtl of wb_counter is
  signal enable    : std_ulogic := '0';
  -- CHANGED: register is now 3 bits wide (0 to 7)
  signal count_reg : unsigned(2 downto 0) := (others => '0'); 
  signal prescaler : unsigned(23 downto 0) := (others => '0');
  signal ack_reg   : std_ulogic := '0';
begin

  -- Wishbone Acknowledge
  process(clk_i) begin
    if rising_edge(clk_i) then
      if rstn_i = '0' then ack_reg <= '0';
      else
        if (wb_cyc_i = '1' and wb_stb_i = '1' and ack_reg = '0') then ack_reg <= '1';
        else ack_reg <= '0'; end if;
      end if;
    end if;
  end process;
  wb_ack_o <= ack_reg;

  -- 3-Bit Counter Logic
  process(clk_i) begin
    if rising_edge(clk_i) then
      if rstn_i = '0' then
        enable <= '0'; count_reg <= (others => '0'); prescaler <= (others => '0');
      else
        -- Handle CPU Enable/Disable
        if (wb_cyc_i = '1' and wb_stb_i = '1' and wb_we_i = '1' and ack_reg = '0') then
          if wb_adr_i(2) = '0' then enable <= wb_dat_i(0); end if;
        end if;

        -- Hardware counting
        if enable = '1' then
          if prescaler = 12000000 then -- ~1 second delay at 12MHz
            prescaler <= (others => '0');
            count_reg <= count_reg + 1; -- Automatically wraps 7 -> 0
          else
            prescaler <= prescaler + 1;
          end if;
        end if;
      end if;
    end if;
  end process;

  -- Bus Read Logic
  process(wb_adr_i, enable, count_reg) begin
    wb_dat_o <= (others => '0'); 
    if wb_adr_i(2) = '0' then 
      wb_dat_o(0) <= enable;          
    else 
      -- Send only the 3 bits to the CPU, others stay 0
      wb_dat_o(2 downto 0) <= std_ulogic_vector(count_reg); 
    end if;
  end process;
end rtl;