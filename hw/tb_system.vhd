-- ============================================================================
-- tb_system.vhd  -  Full-system simulation: the real FPGA top level
-- (neorv32_test_setup_approm) running the C program from the IMEM image.
-- Everything the program prints on UART0 is written to uart0.log.
-- Run it with hw/run_system_sim.bat.
-- File type: VHDL 2008
-- ============================================================================
library ieee;
use ieee.std_logic_1164.all;

library neorv32;

entity tb_system is
end tb_system;

architecture sim of tb_system is

    constant CLK_PERIOD : time := 83.333 ns;   -- 12 MHz, same as the Cmod A7 board

    signal clk  : std_ulogic := '0';
    signal btn  : std_ulogic := '1';           -- reset button pressed at start
    signal txd  : std_ulogic;
    signal gpio : std_ulogic_vector(7 downto 0);

begin

    clk <= not clk after CLK_PERIOD / 2;
    btn <= '1', '0' after 2 us;                -- release the reset button

    dut : entity neorv32.neorv32_test_setup_approm
        generic map (
            BOOT_MODE => 2                     -- program preloaded from neorv32_imem_image.vhd
        )
        port map (
            clk_i       => clk,
            rstn_i      => btn,
            uart0_txd_o => txd,
            uart0_rxd_i => '1',                -- nothing sent to the CPU
            gpio_o      => gpio
        );

    -- prints every received character and writes it to uart0.log
    uart_rx : entity work.sim_uart_rx
        generic map (
            NAME => "uart0",
            FCLK => 12.0e6,
            BAUD => 19200.0
        )
        port map (
            clk => clk,
            rxd => txd
        );

end sim;
