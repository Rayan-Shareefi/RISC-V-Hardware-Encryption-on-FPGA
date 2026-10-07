-- ============================================================================
-- crypto_accel.vhd  -  Crypto accelerator cores  -  ONE FILE
--
-- Contents (each part must be defined before it is used):
--   Part 1  chacha20_core   ChaCha20 block encryption (RFC 8439)
--   Part 2  crypto_accel    TOP: register map + control, used by the CPU's CFU
--   (Poly1305 and Keccak are added to this file in later phases)
--
-- Byte order (same as poly1305_mac / keccak_hash): byte 0 is in bits 7..0,
-- so 32-bit word i (little-endian, as in RFC 8439) is bits 32*i+31 .. 32*i.
--
-- File type in Vivado: VHDL 2008
-- ============================================================================


-- ============================================================================
-- Part 1: chacha20_core - encrypts one 64-byte block
-- ============================================================================
-- Pulse start for one clock, then wait for done:
--   start edge     : load the 4x4 state (constants, key, counter, nonce)
--   next 10 clocks : one double round per clock (column round + diagonal round)
--   10th clock     : data_out = (state + initial state) xor data_in, done = 1
-- Latency: 10 clock cycles from the start edge to done.
--
-- done stays 1 until the next start, so the CPU cannot miss it.
-- key, nonce, counter and data_in must stay stable until done
-- (the initial state is plain wiring from these inputs, no extra registers).
-- ============================================================================
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity chacha20_core is
    port (
        clk      : in  std_logic;
        rst      : in  std_logic;                       -- synchronous, active high
        start    : in  std_logic;                       -- 1-clock pulse: encrypt one block
        key      : in  std_logic_vector(255 downto 0);  -- 32 bytes
        nonce    : in  std_logic_vector(95 downto 0);   -- 12 bytes
        counter  : in  std_logic_vector(31 downto 0);   -- block counter
        data_in  : in  std_logic_vector(511 downto 0);  -- 64 bytes plaintext
        data_out : out std_logic_vector(511 downto 0);  -- 64 bytes ciphertext
        busy     : out std_logic;                       -- 1 while computing
        done     : out std_logic                        -- 1 when data_out is valid
    );
end chacha20_core;

architecture rtl of chacha20_core is

    type state_t is array (0 to 15) of unsigned(31 downto 0);

    -- one quarter round on words a, b, c, d of the state (RFC 8439, 2.1)
    function quarter_round(s : state_t; a, b, c, d : natural) return state_t is
        variable t : state_t := s;
    begin
        t(a) := t(a) + t(b);  t(d) := rotate_left(t(d) xor t(a), 16);
        t(c) := t(c) + t(d);  t(b) := rotate_left(t(b) xor t(c), 12);
        t(a) := t(a) + t(b);  t(d) := rotate_left(t(d) xor t(a), 8);
        t(c) := t(c) + t(d);  t(b) := rotate_left(t(b) xor t(c), 7);
        return t;
    end function;

    -- one double round = column round + diagonal round (RFC 8439, 2.3)
    -- the 4 quarter rounds of each half are independent, so they run in parallel
    function double_round(s : state_t) return state_t is
        variable t : state_t := s;
    begin
        t := quarter_round(t, 0, 4,  8, 12);   -- columns
        t := quarter_round(t, 1, 5,  9, 13);
        t := quarter_round(t, 2, 6, 10, 14);
        t := quarter_round(t, 3, 7, 11, 15);
        t := quarter_round(t, 0, 5, 10, 15);   -- diagonals
        t := quarter_round(t, 1, 6, 11, 12);
        t := quarter_round(t, 2, 7,  8, 13);
        t := quarter_round(t, 3, 4,  9, 14);
        return t;
    end function;

    signal init_s  : state_t;                                    -- initial state (wiring)
    signal x       : state_t := (others => (others => '0'));     -- working state
    signal rnd     : unsigned(3 downto 0) := (others => '0');    -- double round 0..9
    signal running : std_logic := '0';
    signal done_r  : std_logic := '0';
    signal out_r   : std_logic_vector(511 downto 0) := (others => '0');

begin

    -- initial state: "expand 32-byte k", key, counter, nonce
    init_s(0) <= x"61707865";
    init_s(1) <= x"3320646e";
    init_s(2) <= x"79622d32";
    init_s(3) <= x"6b206574";
    gen_key : for i in 0 to 7 generate
        init_s(4 + i) <= unsigned(key(32 * i + 31 downto 32 * i));
    end generate;
    init_s(12) <= unsigned(counter);
    gen_nonce : for i in 0 to 2 generate
        init_s(13 + i) <= unsigned(nonce(32 * i + 31 downto 32 * i));
    end generate;

    process (clk)
        variable nx : state_t;
    begin
        if rising_edge(clk) then
            if rst = '1' then
                running <= '0';
                done_r  <= '0';
                rnd     <= (others => '0');
            elsif start = '1' then
                x       <= init_s;
                rnd     <= (others => '0');
                running <= '1';
                done_r  <= '0';
            elsif running = '1' then
                nx := double_round(x);
                x  <= nx;
                if rnd = 9 then
                    -- last round: add the initial state, then xor with the plaintext
                    for i in 0 to 15 loop
                        out_r(32 * i + 31 downto 32 * i) <=
                            std_logic_vector(nx(i) + init_s(i)) xor data_in(32 * i + 31 downto 32 * i);
                    end loop;
                    running <= '0';
                    done_r  <= '1';
                else
                    rnd <= rnd + 1;
                end if;
            end if;
        end if;
    end process;

    data_out <= out_r;
    busy     <= running;
    done     <= done_r;

end rtl;


-- ============================================================================
-- Part 2: crypto_accel - TOP (register map + control)
-- ============================================================================
-- The CPU talks to the accelerator through 32-bit registers. In this project
-- the CPU's CFU (custom instructions, neorv32_cpu_alu_cfu.vhd) drives this
-- port, but nothing here depends on the CFU, so a memory-mapped wrapper could
-- use it the same way.
--
-- Register map (index = 8-bit register address):
--   0x00-0x07  W  ChaCha20 key        (word 0 = key bytes 0..3, write-only)
--   0x08-0x0A  W  ChaCha20 nonce      (word 0 = nonce bytes 0..3)
--   0x0B       W  ChaCha20 block counter
--   0x0C       R  ChaCha20 status     bit 0 = done, bit 1 = busy
--   0x10-0x1F  W  ChaCha20 plaintext  (16 words = 64 bytes)
--              R  ChaCha20 ciphertext (rvalid = 0 while ChaCha20 is busy)
--
-- Writing while a unit is busy changes its inputs: always read the result
-- first (the read waits for it), then write the next block.
-- ============================================================================
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity crypto_accel is
    port (
        clk          : in  std_logic;
        rstn         : in  std_logic;                      -- active low (as in NEORV32)
        -- register write
        we           : in  std_logic;                      -- 1 clock: write wdata to waddr
        waddr        : in  std_logic_vector(7 downto 0);
        wdata        : in  std_logic_vector(31 downto 0);
        -- register read (combinational)
        raddr        : in  std_logic_vector(7 downto 0);
        rdata        : out std_logic_vector(31 downto 0);
        rvalid       : out std_logic;                      -- 0 = result not ready yet, wait
        -- control
        start_chacha : in  std_logic;                      -- 1 clock: encrypt one block
        busy         : out std_logic                       -- 1 while any unit is computing
    );
end crypto_accel;

architecture rtl of crypto_accel is

    signal rst       : std_logic;

    -- ChaCha20 input registers (held stable while the core runs)
    signal ch_key    : std_logic_vector(255 downto 0) := (others => '0');
    signal ch_nonce  : std_logic_vector(95 downto 0)  := (others => '0');
    signal ch_ctr    : std_logic_vector(31 downto 0)  := (others => '0');
    signal ch_din    : std_logic_vector(511 downto 0) := (others => '0');
    signal ch_dout   : std_logic_vector(511 downto 0);
    signal ch_busy   : std_logic;
    signal ch_done   : std_logic;

begin

    rst <= not rstn;

    u_chacha : entity work.chacha20_core
        port map (
            clk      => clk,
            rst      => rst,
            start    => start_chacha,
            key      => ch_key,
            nonce    => ch_nonce,
            counter  => ch_ctr,
            data_in  => ch_din,
            data_out => ch_dout,
            busy     => ch_busy,
            done     => ch_done
        );

    -- register write
    process (clk)
    begin
        if rising_edge(clk) then
            if we = '1' and waddr(7 downto 5) = "000" then
                for k in 0 to 7 loop
                    if unsigned(waddr(4 downto 0)) = k then
                        ch_key(32 * k + 31 downto 32 * k) <= wdata;
                    end if;
                end loop;
                for k in 0 to 2 loop
                    if unsigned(waddr(4 downto 0)) = 8 + k then
                        ch_nonce(32 * k + 31 downto 32 * k) <= wdata;
                    end if;
                end loop;
                if unsigned(waddr(4 downto 0)) = 11 then
                    ch_ctr <= wdata;
                end if;
                for k in 0 to 15 loop
                    if unsigned(waddr(4 downto 0)) = 16 + k then
                        ch_din(32 * k + 31 downto 32 * k) <= wdata;
                    end if;
                end loop;
            end if;
        end if;
    end process;

    -- register read
    process (raddr, ch_dout, ch_done, ch_busy)
    begin
        rdata  <= (others => '0');
        rvalid <= '1';
        if raddr(7 downto 5) = "000" then
            if unsigned(raddr(4 downto 0)) = 12 then
                rdata(0) <= ch_done;
                rdata(1) <= ch_busy;
            end if;
            for k in 0 to 15 loop
                if unsigned(raddr(4 downto 0)) = 16 + k then
                    rdata  <= ch_dout(32 * k + 31 downto 32 * k);
                    rvalid <= not ch_busy;
                end if;
            end loop;
        end if;
    end process;

    busy <= ch_busy;

end rtl;
