library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity wb_adder is
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
end wb_adder;

architecture rtl of wb_adder is
  signal reg_a   : unsigned(31 downto 0) := (others => '0');
  signal reg_b   : unsigned(31 downto 0) := (others => '0');
  signal res_c   : unsigned(31 downto 0) := (others => '0');
  signal ack_reg : std_ulogic := '0';
begin
  res_c <= reg_a + reg_b; -- Hardware Math

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

  process(clk_i) begin
    if rising_edge(clk_i) then
      if rstn_i = '0' then
        reg_a <= (others => '0'); reg_b <= (others => '0');
      else
        if (wb_cyc_i = '1' and wb_stb_i = '1' and wb_we_i = '1' and ack_reg = '0') then
          if wb_adr_i(3 downto 2) = "00" then reg_a <= unsigned(wb_dat_i); end if;
          if wb_adr_i(3 downto 2) = "01" then reg_b <= unsigned(wb_dat_i); end if;
        end if;
      end if;
    end if;
  end process;

  process(wb_adr_i, reg_a, reg_b, res_c) begin
    wb_dat_o <= (others => '0'); 
    if wb_adr_i(3 downto 2) = "00" then wb_dat_o <= std_ulogic_vector(reg_a);
    elsif wb_adr_i(3 downto 2) = "01" then wb_dat_o <= std_ulogic_vector(reg_b);
    elsif wb_adr_i(3 downto 2) = "10" then wb_dat_o <= std_ulogic_vector(res_c);
    end if;
  end process;
end rtl;