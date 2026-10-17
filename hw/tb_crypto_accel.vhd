-- ============================================================================
-- tb_crypto_accel.vhd  -  Self-checking testbench for crypto_accel.vhd
--
-- ChaCha20 tests (expected values from RFC 8439, cross-checked with the project-1
-- C reference chacha20_block):
--   1) RFC 8439 2.3.2  block function     (plaintext = zeros -> keystream)
--   2) RFC 8439 2.4.2  "sunscreen", block 1 (counter = 1)
--   3) RFC 8439 2.4.2  "sunscreen", block 2 (counter = 2, last 14 bytes zero)
--   4) project-1 test  key = 0, nonce = 0, counter = 1, "Hello my chacha20"
-- For every test it also checks: done goes low on start, busy is high while
-- computing, the latency, and that done + data_out stay stable afterwards.
--
-- Poly1305 tests (tb_poly1305_vectors_pkg.vhd, made by
-- scripts/gen_poly1305_vectors.py): the official RFC 8439 vectors that fit in
-- 64 bytes (2.5.2, A.3 #1, #5-#11, incl. the h >= p edge cases) and every
-- message length 0..64. Also checks done low on start, done + tag stable after.
--
-- Keccak-256 tests (tb_keccak_vectors_pkg.vhd, made by
-- scripts/gen_keccak_vectors.py): Keccak-256 known values, the pk/ test message and
-- every message length 0..135 (one block). Also checks the 24-cycle latency.
--
-- Long messages (added 2026-10-08, init/final control):
--   Poly1305: RFC 8439 A.3 #2-#4 and the AEAD MAC input of RFC 8439 2.8.2,
--             sent in 64-byte pieces and again in 16-byte pieces (the key is
--             given only with the first piece)
--   Keccak:   136..500 bytes, sent as 136-byte blocks + a final block
-- TOP (crypto_accel, register interface as the CPU uses it): ChaCha20 block,
-- Keccak 135 bytes in one block with the reset control value, Keccak 300 bytes
-- in blocks, and the AEAD Poly1305 tag in 64-byte pieces.
--
-- Prints PASS/FAIL per test and a final summary.
-- File type in Vivado: VHDL 2008
-- ============================================================================
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library work;
use work.tb_poly1305_vectors.all;
use work.tb_keccak_vectors.all;

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

    -- Poly1305 DUT signals
    signal po_start : std_logic := '0';
    signal po_key   : std_logic_vector(255 downto 0) := (others => '0');
    signal po_msg   : std_logic_vector(511 downto 0) := (others => '0');
    signal po_len   : std_logic_vector(6 downto 0)   := (others => '0');
    signal po_init  : std_logic := '1';
    signal po_final : std_logic := '1';
    signal po_tag   : std_logic_vector(127 downto 0);
    signal po_done  : std_logic;

    -- Keccak DUT signals
    signal ke_start  : std_logic := '0';
    signal ke_msg    : std_logic_vector(1087 downto 0) := (others => '0');
    signal ke_len    : std_logic_vector(7 downto 0)    := (others => '0');
    signal ke_init   : std_logic := '1';
    signal ke_final  : std_logic := '1';
    signal ke_digest : std_logic_vector(255 downto 0);
    signal ke_done   : std_logic;

    -- TOP (crypto_accel) signals: the register interface the CPU uses
    signal t_rstn     : std_logic;
    signal t_we       : std_logic := '0';
    signal t_waddr    : std_logic_vector(7 downto 0)  := (others => '0');
    signal t_wdata    : std_logic_vector(31 downto 0) := (others => '0');
    signal t_raddr    : std_logic_vector(7 downto 0)  := (others => '0');
    signal t_rdata    : std_logic_vector(31 downto 0);
    signal t_rvalid   : std_logic;
    signal t_start_ch : std_logic := '0';
    signal t_start_po : std_logic := '0';
    signal t_start_ke : std_logic := '0';
    signal t_busy     : std_logic;

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

    dut_poly : entity work.poly1305_mac
        port map (
            clk     => clk,
            rst     => rst,
            start   => po_start,
            key     => po_key,
            msg     => po_msg,
            msg_len => po_len,
            init    => po_init,
            final   => po_final,
            tag     => po_tag,
            done    => po_done
        );

    dut_keccak : entity work.keccak_hash
        port map (
            clk     => clk,
            rst     => rst,
            start   => ke_start,
            msg     => ke_msg,
            msg_len => ke_len,
            init    => ke_init,
            final   => ke_final,
            digest  => ke_digest,
            done    => ke_done
        );

    t_rstn <= not rst;

    dut_top : entity work.crypto_accel
        port map (
            clk          => clk,
            rstn         => t_rstn,
            we           => t_we,
            waddr        => t_waddr,
            wdata        => t_wdata,
            raddr        => t_raddr,
            rdata        => t_rdata,
            rvalid       => t_rvalid,
            start_chacha => t_start_ch,
            start_poly   => t_start_po,
            start_keccak => t_start_ke,
            busy         => t_busy
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

        -- one Poly1305 tag; returns ok and the latency (start edge -> done)
        procedure run_poly(tv : poly_tv_t; variable ok : out boolean; variable cycles : out natural) is
            variable n : natural := 0;
        begin
            ok := true;
            wait until rising_edge(clk);
            po_key   <= tv.key;
            po_msg   <= tv.msg;
            po_len   <= std_logic_vector(to_unsigned(tv.len, 7));
            po_start <= '1';
            wait until rising_edge(clk);           -- circuit samples start here
            po_start <= '0';
            po_key   <= (others => '0');           -- inputs may change after start
            po_msg   <= (others => '0');
            wait for 1 ns;
            if po_done /= '0' then
                report tv.name & ": done did not go low after start" severity error;
                ok := false;
            end if;
            loop
                wait until rising_edge(clk);
                wait for 1 ns;
                n := n + 1;
                exit when po_done = '1' or n > 1000;
            end loop;
            cycles := n;
            if po_tag /= tv.tag then
                report tv.name & ": WRONG tag" & LF &
                       "   got      " & hex(po_tag) & LF &
                       "   expected " & hex(tv.tag) severity error;
                ok := false;
            end if;
            for i in 1 to 3 loop
                wait until rising_edge(clk);
            end loop;
            wait for 1 ns;
            if po_done /= '1' or po_tag /= tv.tag then
                report tv.name & ": done/tag did not stay stable" severity error;
                ok := false;
            end if;
        end procedure;

        -- one Keccak-256 digest; returns ok and the latency (start edge -> done)
        procedure run_keccak(tv : keccak_tv_t; variable ok : out boolean; variable cycles : out natural) is
            variable n : natural := 0;
        begin
            ok := true;
            wait until rising_edge(clk);
            ke_msg   <= tv.msg;
            ke_len   <= std_logic_vector(to_unsigned(tv.len, 8));
            ke_start <= '1';
            wait until rising_edge(clk);           -- circuit samples start here
            ke_start <= '0';
            ke_msg   <= (others => '0');           -- inputs may change after start
            wait for 1 ns;
            if ke_done /= '0' then
                report tv.name & ": done did not go low after start" severity error;
                ok := false;
            end if;
            loop
                wait until rising_edge(clk);
                wait for 1 ns;
                n := n + 1;
                exit when ke_done = '1' or n > 1000;
            end loop;
            cycles := n;
            if ke_digest /= tv.digest then
                report tv.name & ": WRONG digest" & LF &
                       "   got      " & hex(ke_digest) & LF &
                       "   expected " & hex(tv.digest) severity error;
                ok := false;
            end if;
            for i in 1 to 3 loop
                wait until rising_edge(clk);
            end loop;
            wait for 1 ns;
            if ke_done /= '1' or ke_digest /= tv.digest then
                report tv.name & ": done/digest did not stay stable" severity error;
                ok := false;
            end if;
        end procedure;

        -- long Poly1305 message in pieces of "chunk" bytes (16, 32, 48 or 64):
        -- init = 1 only on the first piece (the key is given only there),
        -- final = 1 only on the last piece; h is kept in between
        procedure run_poly_long(tv : poly_long_tv_t; chunk : natural;
                                variable ok : out boolean; variable cycles : out natural) is
            variable piece  : std_logic_vector(511 downto 0);
            variable off, n, cnt, pieces : natural := 0;
            variable left   : natural;
        begin
            ok := true; off := 0; cnt := 0; pieces := 0; left := tv.len;
            loop
                if left > chunk then n := chunk; else n := left; end if;
                piece := (others => '0');
                for i in 0 to n - 1 loop
                    piece(8 * i + 7 downto 8 * i) := tv.msg(8 * (off + i) + 7 downto 8 * (off + i));
                end loop;
                wait until rising_edge(clk);
                if pieces = 0 then po_key <= tv.key; po_init <= '1';
                else               po_key <= (others => '0'); po_init <= '0'; end if;
                if left > chunk then po_final <= '0'; else po_final <= '1'; end if;
                po_msg   <= piece;
                po_len   <= std_logic_vector(to_unsigned(n, 7));
                po_start <= '1';
                wait until rising_edge(clk);
                po_start <= '0';
                po_key   <= (others => '0');
                po_msg   <= (others => '0');
                loop
                    wait until rising_edge(clk);
                    wait for 1 ns;
                    cnt := cnt + 1;
                    exit when po_done = '1' or cnt > 20000;
                end loop;
                pieces := pieces + 1;
                exit when left <= chunk;
                off := off + n;
                left := left - n;
            end loop;
            po_init  <= '1';
            po_final <= '1';
            cycles := cnt;
            if po_tag /= tv.tag then
                report tv.name & " in " & integer'image(chunk) & "-byte pieces: WRONG tag" & LF &
                       "   got      " & hex(po_tag) & LF &
                       "   expected " & hex(tv.tag) severity error;
                ok := false;
            end if;
        end procedure;

        -- long Keccak message: 136-byte blocks (final = 0), then the rest (final = 1)
        procedure run_keccak_long(tv : keccak_long_tv_t; variable ok : out boolean;
                                  variable cycles : out natural; variable blocks : out natural) is
            variable blk  : std_logic_vector(1087 downto 0);
            variable off, n, cnt, nb : natural := 0;
            variable left : natural;
            variable fin  : boolean;
        begin
            ok := true; off := 0; cnt := 0; nb := 0; left := tv.len;
            loop
                fin := left < 136;
                if fin then n := left; else n := 136; end if;
                blk := (others => '0');
                for i in 0 to n - 1 loop
                    blk(8 * i + 7 downto 8 * i) := tv.msg(8 * (off + i) + 7 downto 8 * (off + i));
                end loop;
                wait until rising_edge(clk);
                if nb = 0 then ke_init <= '1'; else ke_init <= '0'; end if;
                if fin then ke_final <= '1'; else ke_final <= '0'; end if;
                ke_msg   <= blk;
                ke_len   <= std_logic_vector(to_unsigned(n, 8));
                ke_start <= '1';
                wait until rising_edge(clk);
                ke_start <= '0';
                ke_msg   <= (others => '0');
                loop
                    wait until rising_edge(clk);
                    wait for 1 ns;
                    cnt := cnt + 1;
                    exit when ke_done = '1' or cnt > 5000;
                end loop;
                nb := nb + 1;
                exit when fin;
                off := off + 136;
                left := left - 136;
            end loop;
            ke_init  <= '1';
            ke_final <= '1';
            cycles := cnt;
            blocks := nb;
            if ke_digest /= tv.digest then
                report "Keccak-256 " & integer'image(tv.len) & " bytes: WRONG digest" & LF &
                       "   got      " & hex(ke_digest) & LF &
                       "   expected " & hex(tv.digest) severity error;
                ok := false;
            end if;
        end procedure;

        -- TOP register access, the way the CPU's custom instructions do it
        procedure top_write(addr : natural; data : std_logic_vector(31 downto 0)) is
        begin
            wait until rising_edge(clk);
            t_waddr <= std_logic_vector(to_unsigned(addr, 8));
            t_wdata <= data;
            t_we    <= '1';
            wait until rising_edge(clk);
            t_we    <= '0';
        end procedure;

        procedure top_write_n(addr : natural; n : natural) is   -- write the number n
        begin
            top_write(addr, std_logic_vector(to_unsigned(n, 32)));
        end procedure;

        procedure top_read(addr : natural; variable data : out std_logic_vector(31 downto 0)) is
            variable cnt : natural := 0;
        begin
            wait until rising_edge(clk);
            t_raddr <= std_logic_vector(to_unsigned(addr, 8));
            wait for 1 ns;
            while t_rvalid /= '1' and cnt < 5000 loop          -- the CPU stalls here
                wait until rising_edge(clk);
                wait for 1 ns;
                cnt := cnt + 1;
            end loop;
            data := t_rdata;
        end procedure;

        procedure top_start(which : natural) is              -- 0 ChaCha20, 1 Poly1305, 2 Keccak
        begin
            wait until rising_edge(clk);
            case which is
                when 0      => t_start_ch <= '1';
                when 1      => t_start_po <= '1';
                when others => t_start_ke <= '1';
            end case;
            wait until rising_edge(clk);
            t_start_ch <= '0';
            t_start_po <= '0';
            t_start_ke <= '0';
        end procedure;

        procedure top_report(name : string; ok : boolean) is
        begin
            if ok then
                report "PASS  TOP " & name severity note;
                passed := passed + 1;
            else
                report "FAIL  TOP " & name severity error;
                errors := errors + 1;
            end if;
        end procedure;

        variable p_ok     : boolean;
        variable p_cycles : natural;
        variable p_blocks : natural;
        variable sweep_bad : natural := 0;
        variable k_bad     : natural := 0;
        variable w         : std_logic_vector(31 downto 0);
        variable r512      : std_logic_vector(511 downto 0);
        variable r256      : std_logic_vector(255 downto 0);
        variable r128      : std_logic_vector(127 downto 0);
        variable t_ok      : boolean;
        variable off, n, left : natural;

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

        -- Poly1305: official RFC vectors, one line each
        for v in 0 to POLY_NUM_RFC - 1 loop
            run_poly(POLY_TVS(v), p_ok, p_cycles);
            if p_ok then
                report "PASS  Poly1305 " & POLY_TVS(v).name & " (" & integer'image(POLY_TVS(v).len) &
                       " bytes, " & integer'image(p_cycles) & " cycles)" severity note;
                passed := passed + 1;
            else
                report "FAIL  Poly1305 " & POLY_TVS(v).name severity error;
                errors := errors + 1;
            end if;
        end loop;

        -- Poly1305: every message length 0..64, one summary line
        for v in POLY_NUM_RFC to POLY_TVS'high loop
            run_poly(POLY_TVS(v), p_ok, p_cycles);
            if not p_ok then
                sweep_bad := sweep_bad + 1;
            end if;
        end loop;
        if sweep_bad = 0 then
            report "PASS  Poly1305 every message length 0..64 bytes (64 bytes: " &
                   integer'image(p_cycles) & " cycles)" severity note;
            passed := passed + 1;
        else
            report "FAIL  Poly1305 lengths 0..64: " & integer'image(sweep_bad) & " wrong" severity error;
            errors := errors + 1;
        end if;

        -- Keccak: named messages, one line each
        for v in 0 to KECCAK_NUM_NAMED - 1 loop
            run_keccak(KECCAK_TVS(v), p_ok, p_cycles);
            if p_ok and p_cycles = 24 then
                report "PASS  Keccak-256 " & KECCAK_TVS(v).name & " (" & integer'image(KECCAK_TVS(v).len) &
                       " bytes, " & integer'image(p_cycles) & " cycles)" severity note;
                passed := passed + 1;
            else
                report "FAIL  Keccak-256 " & KECCAK_TVS(v).name & " (" & integer'image(p_cycles) & " cycles)" severity error;
                errors := errors + 1;
            end if;
        end loop;

        -- Keccak: every message length 0..64, one summary line
        for v in KECCAK_NUM_NAMED to KECCAK_TVS'high loop
            run_keccak(KECCAK_TVS(v), p_ok, p_cycles);
            if not p_ok or p_cycles /= 24 then
                k_bad := k_bad + 1;
            end if;
        end loop;
        if k_bad = 0 then
            report "PASS  Keccak-256 every message length 0..135 bytes (one block, 24 cycles each)" severity note;
            passed := passed + 1;
        else
            report "FAIL  Keccak-256 lengths 0..135: " & integer'image(k_bad) & " wrong" severity error;
            errors := errors + 1;
        end if;

        -- ---- long messages (init / final control) ------------------------------
        -- Poly1305: each long vector in 64-byte pieces and again in 16-byte pieces
        for v in POLY_LONG_TVS'range loop
            run_poly_long(POLY_LONG_TVS(v), 64, p_ok, p_cycles);
            t_ok := p_ok;
            n := p_cycles;
            run_poly_long(POLY_LONG_TVS(v), 16, p_ok, p_cycles);
            if t_ok and p_ok then
                report "PASS  Poly1305 " & POLY_LONG_TVS(v).name & " (" & integer'image(POLY_LONG_TVS(v).len) &
                       " bytes in 64-byte pieces: " & integer'image(n) & " cycles; in 16-byte pieces: " &
                       integer'image(p_cycles) & " cycles)" severity note;
                passed := passed + 1;
            else
                report "FAIL  Poly1305 " & POLY_LONG_TVS(v).name & " in pieces" severity error;
                errors := errors + 1;
            end if;
        end loop;

        -- Keccak: 136..500 bytes in 136-byte blocks, one summary line
        k_bad := 0;
        for v in KECCAK_LONG_TVS'range loop
            run_keccak_long(KECCAK_LONG_TVS(v), p_ok, p_cycles, p_blocks);
            if not p_ok or p_cycles /= 24 * p_blocks then
                k_bad := k_bad + 1;
                report "  Keccak-256 " & integer'image(KECCAK_LONG_TVS(v).len) & " bytes: " &
                       integer'image(p_blocks) & " blocks, " & integer'image(p_cycles) & " cycles" severity error;
            end if;
        end loop;
        if k_bad = 0 then
            report "PASS  Keccak-256 long messages 136..500 bytes (2..4 blocks of 136 bytes, 24 cycles per block)" severity note;
            passed := passed + 1;
        else
            report "FAIL  Keccak-256 long messages: " & integer'image(k_bad) & " wrong" severity error;
            errors := errors + 1;
        end if;

        -- ---- TOP: the register interface, as the CPU uses it ---------------------
        -- 1) Keccak, 135 bytes in one block, control register at its reset value (3)
        t_ok := true;
        for k in 0 to 33 loop
            top_write(16#40# + k, KECCAK_TVS(KECCAK_NUM_NAMED + 135).msg(32 * k + 31 downto 32 * k));
        end loop;
        top_write_n(16#62#, 135);
        top_start(2);
        for k in 0 to 7 loop
            top_read(16#68# + k, w);
            r256(32 * k + 31 downto 32 * k) := w;
        end loop;
        if r256 /= KECCAK_TVS(KECCAK_NUM_NAMED + 135).digest then
            report "TOP Keccak 135 bytes: got " & hex(r256) severity error;
            t_ok := false;
        end if;
        top_report("Keccak-256 135 bytes, one block, reset control value", t_ok);

        -- 2) ChaCha20 RFC 8439 2.4.2 block 1
        t_ok := true;
        for k in 0 to 7 loop top_write(16#00# + k, KEY_RFC(32 * k + 31 downto 32 * k)); end loop;
        for k in 0 to 2 loop top_write(16#08# + k, NONCE_242(32 * k + 31 downto 32 * k)); end loop;
        top_write_n(16#0B#, 1);
        r512 := text64(SUNSCREEN(1 to 64));
        for k in 0 to 15 loop top_write(16#10# + k, r512(32 * k + 31 downto 32 * k)); end loop;
        top_start(0);
        for k in 0 to 15 loop
            top_read(16#10# + k, w);
            r512(32 * k + 31 downto 32 * k) := w;
        end loop;
        if r512 /= EXP_242_1 then
            report "TOP ChaCha20: got " & hex(r512) severity error;
            t_ok := false;
        end if;
        top_report("ChaCha20 RFC 8439 2.4.2 block 1", t_ok);

        -- 3) Keccak 300 bytes: two 136-byte blocks + a 28-byte final block
        t_ok := true;
        off := 0;
        left := KECCAK_LONG_TVS(6).len;
        assert left = 300 report "KECCAK_LONG_TVS(6) should be 300 bytes" severity failure;
        loop
            if left < 136 then n := left; else n := 136; end if;
            for k in 0 to (n + 3) / 4 - 1 loop
                top_write(16#40# + k, KECCAK_LONG_TVS(6).msg(8 * off + 32 * k + 31 downto 8 * off + 32 * k));
            end loop;
            top_write_n(16#62#, n);
            if off = 0 and left >= 136 then top_write_n(16#64#, 1);   -- init, not final
            elsif left >= 136 then          top_write_n(16#64#, 0);   -- middle block
            else                            top_write_n(16#64#, 2);   -- final
            end if;
            top_start(2);
            top_read(16#68#, w);                                       -- waits until the block is done
            exit when left < 136;
            off := off + 136;
            left := left - 136;
        end loop;
        for k in 0 to 7 loop
            top_read(16#68# + k, w);
            r256(32 * k + 31 downto 32 * k) := w;
        end loop;
        if r256 /= KECCAK_LONG_TVS(6).digest then
            report "TOP Keccak 300 bytes: got " & hex(r256) severity error;
            t_ok := false;
        end if;
        top_report("Keccak-256 300 bytes in 3 blocks", t_ok);

        -- 4) Poly1305 tag of the RFC 8439 2.8.2 AEAD MAC input, 64-byte pieces
        t_ok := true;
        for k in 0 to 7 loop
            top_write(16#20# + k, POLY_LONG_TVS(POLY_LONG_TVS'high).key(32 * k + 31 downto 32 * k));
        end loop;
        off := 0;
        left := POLY_LONG_TVS(POLY_LONG_TVS'high).len;
        loop
            if left > 64 then n := 64; else n := left; end if;
            for k in 0 to (n + 3) / 4 - 1 loop
                top_write(16#30# + k, POLY_LONG_TVS(POLY_LONG_TVS'high).msg(8 * off + 32 * k + 31 downto 8 * off + 32 * k));
            end loop;
            top_write_n(16#28#, n);
            if off = 0 and left > 64 then top_write_n(16#2A#, 1);     -- init, not final
            elsif left > 64 then          top_write_n(16#2A#, 0);     -- middle piece
            else                          top_write_n(16#2A#, 2);     -- final
            end if;
            top_start(1);
            top_read(16#2C#, w);                                       -- waits until the piece is done
            exit when left <= 64;
            off := off + 64;
            left := left - 64;
        end loop;
        for k in 0 to 3 loop
            top_read(16#2C# + k, w);
            r128(32 * k + 31 downto 32 * k) := w;
        end loop;
        if r128 /= POLY_LONG_TVS(POLY_LONG_TVS'high).tag then
            report "TOP Poly1305 AEAD MAC: got " & hex(r128) severity error;
            t_ok := false;
        end if;
        top_report("Poly1305 RFC 8439 2.8.2 AEAD tag in 64-byte pieces", t_ok);

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
