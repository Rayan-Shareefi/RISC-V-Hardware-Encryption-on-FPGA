-- ============================================================================
-- tb_crypto_accel.vhd  -  Self-checking testbench for crypto_accel.vhd
--
-- ChaCha20 tests (expected values from RFC 8439, cross-checked with the project-1
-- C reference chacha20_block):
--   1) RFC 8439 2.3.2  block function     (plaintext = zeros -> keystream)
--   2) RFC 8439 2.4.2  "sunscreen", block 1 (counter = 1)
--   3) RFC 8439 2.4.2  "sunscreen", block 2 (counter = 2, last 14 bytes zero)
--   4) the project-1 test   key = 0, nonce = 0, counter = 1, "Hello my chacha20"
-- For every test it also checks: done goes low on start, busy is high while
-- computing, the latency, and that done + data_out stay stable afterwards.
--
-- Prints PASS/FAIL per test and a final summary.
-- File type in Vivado: VHDL 2008
-- ============================================================================
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity tb_crypto_accel is
end tb_crypto_accel;

architecture sim of tb_crypto_accel is

    constant CLK_PERIOD : time := 83.333 ns;   -- 12 MHz, same as the Cmod A7 board

    -- hex string -> bytes, first two hex digits = byte 0 = bits 7..0
    function bytes(h : string) return std_logic_vector is
        constant n  : natural := h'length / 2;
        variable hs : string(1 to h'length) := h;
        variable r  : std_logic_vector(8 * n - 1 downto 0);
        function nib(c : character) return std_logic_vector is
            variable v : natural := 0;
        begin
            if c >= '0' and c <= '9' then
                v := character'pos(c) - character'pos('0');
            elsif c >= 'a' and c <= 'f' then
                v := character'pos(c) - character'pos('a') + 10;
            elsif c >= 'A' and c <= 'F' then
                v := character'pos(c) - character'pos('A') + 10;
            else
                report "bad hex digit" severity failure;
            end if;
            return std_logic_vector(to_unsigned(v, 4));
        end function;
    begin
        for i in 0 to n - 1 loop
            r(8 * i + 7 downto 8 * i + 4) := nib(hs(2 * i + 1));
            r(8 * i + 3 downto 8 * i)     := nib(hs(2 * i + 2));
        end loop;
        return r;
    end function;

    -- text -> 64 bytes (byte 0 = first character), rest filled with zeros
    function text64(s : string) return std_logic_vector is
        variable ss : string(1 to s'length) := s;
        variable r  : std_logic_vector(511 downto 0) := (others => '0');
    begin
        for i in 0 to s'length - 1 loop
            exit when i = 64;
            r(8 * i + 7 downto 8 * i) := std_logic_vector(to_unsigned(character'pos(ss(i + 1)), 8));
        end loop;
        return r;
    end function;

    -- bytes -> hex string, byte 0 first (same order as the RFC listings)
    function hex(v : std_logic_vector) return string is
        constant HEXC : string(1 to 16) := "0123456789abcdef";
        constant n    : natural := v'length / 8;
        variable vv   : std_logic_vector(v'length - 1 downto 0) := v;
        variable r    : string(1 to 2 * n);
    begin
        for i in 0 to n - 1 loop
            r(2 * i + 1) := HEXC(to_integer(unsigned(vv(8 * i + 7 downto 8 * i + 4))) + 1);
            r(2 * i + 2) := HEXC(to_integer(unsigned(vv(8 * i + 3 downto 8 * i))) + 1);
        end loop;
        return r;
    end function;

    -- ---- test vectors -------------------------------------------------------
    constant KEY_RFC   : std_logic_vector(255 downto 0) :=
        bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    constant NONCE_232 : std_logic_vector(95 downto 0) := bytes("000000090000004a00000000");
    constant NONCE_242 : std_logic_vector(95 downto 0) := bytes("000000000000004a00000000");
    constant SUNSCREEN : string :=
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    constant EXP_232   : std_logic_vector(511 downto 0) := bytes(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" &
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    constant EXP_242_1 : std_logic_vector(511 downto 0) := bytes(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" &
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8");
    -- first 50 bytes from the RFC, last 14 bytes = keystream (plaintext there is 0)
    constant EXP_242_2 : std_logic_vector(511 downto 0) := bytes(
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" &
        "5af90bbf74a35be6b40b8eedf2785e42874d740373201aa188fbbce83991c4ed");
    constant EXP_PROJECT1 : std_logic_vector(511 downto 0) := bytes(
        "d7628bd23a715503b8d9ff1d1045693ffb0f29a048e3656912c6533e32ee7aed" &
        "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");

    constant EXPECTED_LATENCY : natural := 10;

    -- ---- DUT signals --------------------------------------------------------
    signal clk      : std_logic := '0';
    signal rst      : std_logic := '1';
    signal start    : std_logic := '0';
    signal key      : std_logic_vector(255 downto 0) := (others => '0');
    signal nonce    : std_logic_vector(95 downto 0)  := (others => '0');
    signal counter  : std_logic_vector(31 downto 0)  := (others => '0');
    signal data_in  : std_logic_vector(511 downto 0) := (others => '0');
    signal data_out : std_logic_vector(511 downto 0);
    signal busy     : std_logic;
    signal done     : std_logic;

    signal sim_done : boolean := false;

begin

    clk_gen : process
    begin
        while not sim_done loop
            clk <= '0'; wait for CLK_PERIOD / 2;
            clk <= '1'; wait for CLK_PERIOD / 2;
        end loop;
        wait;
    end process;

    dut : entity work.chacha20_core
        port map (
            clk      => clk,
            rst      => rst,
            start    => start,
            key      => key,
            nonce    => nonce,
            counter  => counter,
            data_in  => data_in,
            data_out => data_out,
            busy     => busy,
            done     => done
        );

    stim : process
        variable errors : natural := 0;
        variable passed : natural := 0;

        procedure run_test(name    : string;
                           k       : std_logic_vector(255 downto 0);
                           n       : std_logic_vector(95 downto 0);
                           ctr     : natural;
                           pt      : std_logic_vector(511 downto 0);
                           exp     : std_logic_vector(511 downto 0)) is
            variable cycles : natural := 0;
            variable ok     : boolean := true;
        begin
            -- apply inputs and pulse start for one clock
            wait until rising_edge(clk);
            key     <= k;
            nonce   <= n;
            counter <= std_logic_vector(to_unsigned(ctr, 32));
            data_in <= pt;
            start   <= '1';
            wait until rising_edge(clk);           -- core samples start here
            start <= '0';
            wait for 1 ns;
            if done /= '0' then
                report name & ": done did not go low after start" severity error;
                ok := false;
            end if;

            -- count clocks until done (busy must be 1 meanwhile)
            loop
                wait until rising_edge(clk);
                wait for 1 ns;
                cycles := cycles + 1;
                exit when done = '1';
                if busy /= '1' then
                    report name & ": busy is 0 while computing" severity error;
                    ok := false;
                end if;
                if cycles > 100 then
                    report name & ": TIMEOUT, done never came" severity error;
                    ok := false;
                    exit;
                end if;
            end loop;

            if cycles /= EXPECTED_LATENCY then
                report name & ": latency " & integer'image(cycles) & " cycles, expected " &
                       integer'image(EXPECTED_LATENCY) severity error;
                ok := false;
            end if;

            -- check the result
            if data_out /= exp then
                report name & ": WRONG ciphertext" & LF &
                       "   got      " & hex(data_out) & LF &
                       "   expected " & hex(exp) severity error;
                ok := false;
            end if;

            -- done and data_out must stay stable (the CPU may read them later)
            for i in 1 to 5 loop
                wait until rising_edge(clk);
            end loop;
            wait for 1 ns;
            if done /= '1' or data_out /= exp then
                report name & ": done/data_out did not stay stable" severity error;
                ok := false;
            end if;

            if ok then
                report "PASS  " & name & "  (" & integer'image(cycles) & " cycles)" severity note;
                passed := passed + 1;
            else
                report "FAIL  " & name severity error;
                errors := errors + 1;
            end if;
        end procedure;

    begin
        -- reset for a few clocks
        rst <= '1';
        for i in 1 to 3 loop
            wait until rising_edge(clk);
        end loop;
        rst <= '0';

        run_test("RFC 8439 2.3.2 block function", KEY_RFC, NONCE_232, 1,
                 (others => '0'), EXP_232);
        run_test("RFC 8439 2.4.2 sunscreen block 1", KEY_RFC, NONCE_242, 1,
                 text64(SUNSCREEN(1 to 64)), EXP_242_1);
        run_test("RFC 8439 2.4.2 sunscreen block 2", KEY_RFC, NONCE_242, 2,
                 text64(SUNSCREEN(65 to SUNSCREEN'length)), EXP_242_2);
        run_test("Project-1 test (key 0, Hello my chacha20)", (others => '0'), (others => '0'), 1,
                 text64("Hello my chacha20"), EXP_PROJECT1);

        report "==== SUMMARY: " & integer'image(passed) & " passed, " &
               integer'image(errors) & " failed ====" severity note;
        if errors = 0 then
            report "ALL TESTS PASSED" severity note;
        else
            report "SOME TESTS FAILED" severity error;
        end if;

        sim_done <= true;
        wait;
    end process;

end sim;
