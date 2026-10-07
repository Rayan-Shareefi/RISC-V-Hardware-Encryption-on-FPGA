library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity tb_chacha20_encrypt is
end entity;

architecture sim of tb_chacha20_encrypt is
    signal clk   : std_logic := '0';
    signal rst   : std_logic := '1';
    signal start : std_logic := '0';
    signal done  : std_logic;
begin
    clk <= not clk after 5 ns;

    uut: entity work.chacha20_encrypt
        port map (
            clk   => clk,
            rst   => rst,
            start => start,
            done  => done
        );

    process
    begin
        wait for 20 ns;
        rst <= '0';

        wait for 10 ns;
        start <= '1';

        wait for 10 ns;
        start <= '0';

        wait until done = '1';
        wait for 50 ns;

        report "ChaCha20 encryption finished." severity note;
        wait;
    end process;
end architecture;