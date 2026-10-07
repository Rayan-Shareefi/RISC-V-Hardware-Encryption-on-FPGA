-- ============================================================================
-- crypto_accel.vhd  -  Crypto accelerator cores  -  ONE FILE
--
-- Contents (each part must be defined before it is used):
--   Part 1    chacha20_core   ChaCha20 block encryption (RFC 8439)
--   Part 2-8  poly1305_mac    Poly1305 MAC (RFC 8439), from pk/poly1305_mac.vhd
--   Part 9    crypto_accel    TOP: register map + control, used by the CPU's CFU
--   (Keccak is added to this file in a later phase)
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
-- Parts 2-8: Poly1305 MAC (copied from pk/poly1305_mac.vhd, logic unchanged)
--   Parts 2-7: Poly1305 core from github.com/FPGA-House-AG/ChaCha20Poly1305
--   Part 8:    poly1305_mac controller, written for this project
-- ----------------------------------------------------------------------------
-- License of parts 1-6:
-- BSD 3-Clause License
--
-- Copyright 2023 BrightAI BV
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are met:
--
-- 1. Redistributions of source code must retain the above copyright notice, this
--    list of conditions and the following disclaimer.
--
-- 2. Redistributions in binary form must reproduce the above copyright notice,
--    this list of conditions and the following disclaimer in the documentation
--    and/or other materials provided with the distribution.
--
-- 3. Neither the name of the copyright holder nor the names of its
--    contributors may be used to endorse or promote products derived from
--    this software without specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-- DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
-- SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
-- CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
-- OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
-- OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-- ============================================================================


-- ============================================================================
-- Part 2: mult_gen_0 - 17x17 multiplier
-- ============================================================================
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;
  
entity mult_gen_0 IS
  PORT (
    CLK : IN STD_LOGIC;
    A : IN STD_LOGIC_VECTOR(16 DOWNTO 0);
    B : IN STD_LOGIC_VECTOR(16 DOWNTO 0);
    P : OUT STD_LOGIC_VECTOR(33 DOWNTO 0)
  );
END mult_gen_0;
  

architecture Behavioral of mult_gen_0 is

signal A0,B0              : unsigned(16 downto 0);
signal sum0,sum1,sum2                    : unsigned(33 downto 0);

begin

A0 <= unsigned(A);
B0 <= unsigned(B);


process(clk)
begin
if rising_edge(clk) then
-- 3 pipeline stages
sum0 <= A0 * B0;
sum1 <= sum0;
sum2 <= sum1;
end if;
end process;

P <= std_logic_vector(sum2);

end Behavioral;


-- ============================================================================
-- Part 3: mul_36 - 34x34 multiplier
-- ============================================================================
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;
  
entity mul_36 is
  Port (clk			: in  STD_LOGIC;
	    A           : in  unsigned(33 downto 0);
		B           : in  unsigned(33 downto 0);
		data_out    : out unsigned(67 downto 0)
        );
end mul_36;

architecture Behavioral of mul_36 is

signal A0,A1,B0,B1              : unsigned(16 downto 0);
signal mul_res_0,mul_res_1,mul_res_2,mul_res_3 : STD_LOGIC_VECTOR(33 downto 0);
signal sum_0                    : unsigned(34 downto 0);
signal sum_1                    : unsigned(67 downto 0);

component mult_gen_0 IS
  PORT (
    CLK : IN STD_LOGIC;
    A : IN STD_LOGIC_VECTOR(16 DOWNTO 0);
    B : IN STD_LOGIC_VECTOR(16 DOWNTO 0);
    P : OUT STD_LOGIC_VECTOR(33 DOWNTO 0)
  );
END component;

begin



u0: mult_gen_0
  PORT MAP (
    CLK => clk,
    A  => std_logic_vector(A0),
    B  => std_logic_vector(B0),
    P  => mul_res_0
  );
  
  u1: mult_gen_0
  PORT MAP (
    CLK => clk,
    A  => std_logic_vector(A0),
    B  => std_logic_vector(B1),
    P  => mul_res_1
  );
  
  u2: mult_gen_0
  PORT MAP (
    CLK => clk,
    A  => std_logic_vector(A1),
    B  => std_logic_vector(B0),
    P  => mul_res_2
  );
  
  u3: mult_gen_0
  PORT MAP (
    CLK => clk,
    A  => std_logic_vector(A1),
    B  => std_logic_vector(B1),
    P  => mul_res_3
  );
process(clk)
begin
if rising_edge(clk) then

A0 <= A(16 downto 0);
A1 <= A(33 downto 17);
B0 <= B(16 downto 0);
B1 <= B(33 downto 17);
end if;
end process;

process(clk)
begin
if rising_edge(clk) then


sum_0 <= unsigned('0'&mul_res_1)+unsigned(mul_res_2);---to be shifted <<18bit
sum_1 <= unsigned(mul_res_0)+(unsigned(mul_res_3)&"0000000000000000000000000000000000");---to be shifted <<34bit

end if;
end process;

process(clk)
begin
if rising_edge(clk) then

    data_out <= sum_1+(sum_0&"00000000000000000");---to be shifted <<18bit

end if;
end process;


end Behavioral;


-- ============================================================================
-- Part 4: mul_72 - 68x68 multiplier
-- ============================================================================
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;
  
entity mul_72 is
  Port (clk			: in  STD_LOGIC;
	    A           : in  unsigned(67 downto 0);
		B           : in  unsigned(67 downto 0);
		data_out    : out unsigned(135 downto 0)
        );
end mul_72;

architecture Behavioral of mul_72 is

signal A0,A1,B0,B1              : unsigned(33 downto 0);
signal mul_res_0,mul_res_1,mul_res_2,mul_res_3 : unsigned(67 downto 0);
signal sum_0                    : unsigned(68 downto 0);
signal sum_1,temp,temp_1        : unsigned(135 downto 0);
signal sum_0_1,sum_0_2          : unsigned(34 downto 0);
signal sum_0_0                  : unsigned(102 downto 0);
signal data_temp                : unsigned(103 downto 0);


component mul_36 IS
  PORT (
    CLK : IN STD_LOGIC;
    A : IN unsigned(33 DOWNTO 0);
    B : IN unsigned(33 DOWNTO 0);
    data_out : OUT unsigned(67 DOWNTO 0)
  );
END component;

begin



u0: mul_36
  PORT MAP (
    CLK => clk,
    A  => (A0),
    B  => (B0),
    data_out  => mul_res_0
  );
  
u1: mul_36
  PORT MAP (
    CLK => clk,
    A  => (A0),
    B  => (B1),
    data_out  => mul_res_1
  );
  
  u2: mul_36
  PORT MAP (
    CLK => clk,
    A  => (A1),
    B  => (B0),
    data_out  => mul_res_2
  );
  
  u3: mul_36
  PORT MAP (
    CLK => clk,
    A  => (A1),
    B  => (B1),
    data_out  => mul_res_3
  );
  
  
  process(clk)
begin
if rising_edge(clk) then
A0 <= A(33 downto 0);
A1 <= A(67 downto 34);
B0 <= B(33 downto 0);
B1 <= B(67 downto 34);
end if;
end process;



process(clk)
begin
if rising_edge(clk) then

sum_0 <= unsigned('0'&mul_res_1)+unsigned(mul_res_2);---to be shifted <<34bit
sum_1 <= unsigned(mul_res_0)+(unsigned(mul_res_3)&x"00000000000000000");---to be shifted <<68bit

end if;
end process;

process(clk)
begin
if rising_edge(clk) then

    data_out <= sum_1+(sum_0&x"00000000"&"00");--34

end if;
end process;

end Behavioral;


-- ============================================================================
-- Part 5: mul_144 - 136x136 multiplier
-- ============================================================================
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;
  
entity mul_144 is
  Port (clk			: in  STD_LOGIC;
	    A           : in  unsigned(135 downto 0);
		B           : in  unsigned(135 downto 0);
		data_out    : out unsigned(271 downto 0)
        );
end mul_144;

architecture Behavioral of mul_144 is
signal A0,A1,B0,B1              : unsigned(67 downto 0);
signal mul_res_0,mul_res_1,mul_res_2,mul_res_3 : unsigned(135 downto 0);
signal sum_0                    : unsigned(136 downto 0);
signal sum_1,temp_1             : unsigned(271 downto 0);
signal temp_2                   : unsigned(206 downto 0);


component mul_72 IS
  PORT (
    CLK : IN STD_LOGIC;
    A : IN unsigned(67 DOWNTO 0);
    B : IN unsigned(67 DOWNTO 0);
    data_out : OUT unsigned(135 DOWNTO 0)
  );
END component;

begin

A0 <= A(67 downto 0);
A1 <= A(135 downto 68);
B0 <= B(67 downto 0);
B1 <= B(135 downto 68);

u0: mul_72
  PORT MAP (
    CLK => clk,
    A  => (A0),
    B  => (B0),
    data_out  => mul_res_0
  );
  
u1: mul_72
  PORT MAP (
    CLK => clk,
    A  => (A0),
    B  => (B1),
    data_out  => mul_res_1
  );
  
  u2: mul_72
  PORT MAP (
    CLK => clk,
    A  => (A1),
    B  => (B0),
    data_out  => mul_res_2
  );
  
  u3: mul_72
  PORT MAP (
    CLK => clk,
    A  => (A1),
    B  => (B1),
    data_out  => mul_res_3
  );


process(clk)
begin
if rising_edge(clk) then

--sum_0_1 <= unsigned('0'&mul_res_1(67 downto 0)) + unsigned(mul_res_2(67 downto 0));
--sum_0_2 <= unsigned('0'&mul_res_1(135 downto 68)) + unsigned(mul_res_2(135 downto 68));

sum_0 <= unsigned('0'&mul_res_1)+unsigned(mul_res_2);---to be shifted <<68bit
sum_1 <= unsigned(mul_res_0)+(unsigned(mul_res_3)&x"0000000000000000000000000000000000");---to be shifted <<136bit


end if;
end process;

process(clk)
begin
if rising_edge(clk) then
    temp_1 <= sum_1;
    temp_2 <= '0'&sum_1(205 downto 0)+(sum_0&x"00000000000000000");--68

end if;
end process;

process(clk)
begin
if rising_edge(clk) then

--    data_out <= sum_1+(sum_0&x"00000000000000000");--68
data_out <= temp_1(271 downto 206)&x"000000000000000000000000000000000000000000000000000"&"00"+temp_2;
end if;
end process;

end Behavioral;


-- ============================================================================
-- Part 6: mod_red_1305 - reduction mod 2^130 - 5
-- ============================================================================
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;
   
entity mod_red_1305 is
  Port (clk			: in  STD_LOGIC;
	    data_in     : in  unsigned(260 downto 0);
		data_out    : out unsigned(129 downto 0)
        );
end mod_red_1305;

architecture Behavioral of mod_red_1305 is

signal A_1                : unsigned(129 downto 0);
signal B_1                : unsigned(133 downto 0);
signal A_2                : unsigned(129 downto 0);
signal B_2                : unsigned(7 downto 0);
signal A_3                : unsigned(129 downto 0);
signal B_3                : unsigned(3 downto 0);

signal temp_1           : unsigned(130 downto 0);

signal res_1        : unsigned(134 downto 0);
signal res_1_1      : unsigned(80 downto 0);
signal res_1_2      : unsigned(54 downto 0);
signal res_2        : unsigned(130 downto 0);
signal res_2_1      : unsigned(80 downto 0);
signal res_3        : unsigned(130 downto 0);
signal res_3_1      : unsigned(80 downto 0);
signal data_in_1    :unsigned(130 downto 0);
signal data_in_2    :unsigned(132 downto 0);
signal B_1_1        :unsigned(80 downto 0);
signal B_1_2        :unsigned(53 downto 0);

begin

--temp_1 <= ;

data_in_1 <= data_in(260 downto 130);
data_in_2 <= data_in(260 downto 130)&"00";

process(clk)
begin
if rising_edge(clk) then

    A_1 <= data_in(129 downto 0);
    
--    B_1_1 <= '0'&data_in_2(79 downto 0) + data_in_1(79 downto 0);
--    B_1_2 <= '0'&data_in_2(132 downto 80) + data_in_1(130 downto 80);
    
    B_1 <= '0'&data_in_2 + data_in_1;-- * to_unsigned(5, 3);
    
end if;
end process;

--process(clk)
--begin
--if rising_edge(clk) then

--    A_1_1 <= A_1;
--    B_1 <= B_1_2&x"00000000000000000000" + B_1_1;-- * to_unsigned(5, 3);
    
----    B_1 <= data_in_2 + data_in_1;-- * to_unsigned(5, 3);
    
----res_1 <= ('0'&B_1)+A_1;
--end if;
--end process;

process(clk)
begin
if rising_edge(clk) then
    res_1 <= ('0'&B_1)+A_1;
end if;
end process;


process(clk)
begin
if rising_edge(clk) then
    A_2 <= res_1(129 downto 0);
    B_2 <= '0'&res_1(134 downto 130)&"00" + res_1(134 downto 130);-- * to_unsigned(5, 3);
    
end if;
end process;

process(clk)
begin
if rising_edge(clk) then
    res_2   <= '0'&A_2+B_2;
end if;
end process;

--process(clk)
--begin
--if rising_edge(clk) then
--    A_2_1<=A_2;
--    res_2_1 <= ('0'&A_2(79 downto 0))+B_2;
--end if;
--end process;

--process(clk)
--begin
--if rising_edge(clk) then
--    res_2   <= '0'&A_2_1(129 downto 80)&x"00000000000000000000"+res_2_1;
--end if;
--end process;

process(clk)
begin
if rising_edge(clk) then
    A_3 <= res_2(129 downto 0);
--    B_3 <= ("0000"&res_2(130)) * to_unsigned(5, 3);
    B_3 <= ('0'&res_2(130))&"00" + ('0'&res_2(130));-- * to_unsigned(5, 3);
--    res_3 <= ('0'&A_3)+B_3;
    
end if;
end process;

process(clk)
begin
if rising_edge(clk) then
    res_3 <= ('0'&A_3)+B_3;
end if;
end process;


--process(clk)
--begin
--if rising_edge(clk) then
--    A_3_1 <= A_3;
--    res_3_1 <= '0'&A_3(79 downto 0)+B_3;
--end if;
--end process;

--process(clk)
--begin
--if rising_edge(clk) then
--    res_3 <= ('0'&A_3_1(129 downto 80))&x"00000000000000000000"+res_3_1;
--end if;
--end process;

data_out <= res_3(129 downto 0);

end Behavioral;


-- ============================================================================
-- Part 7: Poly1305 - block core
-- ============================================================================
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use ieee.numeric_std.all;

entity Poly1305 is
  Port (clk			    : in  STD_LOGIC;
		acc				: in  unsigned(130 downto 0);
		Blck			: in  unsigned(127 downto 0);
		r				: in  unsigned(127 downto 0);
		s				: in  unsigned(127 downto 0);
		data_out		: out unsigned(129 downto 0)
        );
end Poly1305;

architecture Behavioral of Poly1305 is

function  order_128  (a : unsigned) return unsigned is
	variable a1 : unsigned(127 downto 0):=a;
	variable b1 : unsigned(127 downto 0):=(others=>'0');
begin

b1 := a1(7 downto 0)&a1(15 downto 8)&a1(23 downto 16)&a1(31 downto 24)&a1(39 downto 32)&a1(47 downto 40)&a1(55 downto 48)&a1(63 downto 56)&a1(71 downto 64)&a1(79 downto 72)&a1(87 downto 80)&a1(95 downto 88)&a1(103 downto 96)&a1(111 downto 104)&a1(119 downto 112)&a1(127 downto 120);
return b1;
end order_128;

COMPONENT mul_144 is
  Port (clk			: in  STD_LOGIC;
	    A           : in  unsigned(135 downto 0);
		B           : in  unsigned(135 downto 0);
		data_out    : out unsigned(271 downto 0)
        );
end COMPONENT;

COMPONENT mod_red_1305 is
  Port (clk			: in  STD_LOGIC;
	    data_in     : in  unsigned(260 downto 0);
		data_out    : out unsigned(129 downto 0)
        );
end COMPONENT;

signal res_1   : unsigned(131 downto 0);---132bits
signal r_clmp  : unsigned(127 downto 0);---132bits
signal A       : unsigned(135 downto 0);
signal B       : unsigned(135 downto 0);
signal res_mul : unsigned(271 downto 0);
signal mod_red_in : unsigned(260 downto 0);
signal mod_red_out : unsigned(129 downto 0);
signal res_2   : unsigned(130 downto 0);---132bits


begin

u1: mul_144 Port map
	 (clk	        => clk,
         A	        => A,
         B	        => B,
         data_out	=> res_mul
     );
     
u2: mod_red_1305 Port map
	 (clk	        => clk,
         data_in	=> mod_red_in,
         data_out	=> mod_red_out
     );
     
     

process(clk)
begin
if rising_edge(clk) then

    res_1 <= '0'&acc+('1'&Blck);---131 + 129 = 132
    r_clmp <= order_128(r) and x"0ffffffc0ffffffc0ffffffc0fffffff";
    
end if;
end process;

A <= "0000"&res_1;
B <= x"00"&r_clmp;
mod_red_in <= res_mul(260 downto 0);

process(clk)
begin
if rising_edge(clk) then
--    res_2 <= '0'&mod_red_out+s;---130 + 128 = 131
--    data_out <= res_2(127 downto 0);
data_out <= mod_red_out;--(127 downto 0);
end if;
end process;

end Behavioral;


-- ============================================================================
-- Part 8: poly1305_mac - TOP
-- ============================================================================
-- Top module, same style as chacha20_encrypt: pulse start, wait for done.
-- It wraps the Poly1305 block core (Part 7) and
-- adds a controller (FSM) that does the whole MAC in hardware:
--   1) feeds the message to the core one 16-byte block at a time
--   2) fixes the pad bit of the last (partial) block
--   3) final step: tag = (h mod p + s) mod 2^128
--
-- Byte order (same as the ChaCha20 circuit): byte 0 is in bits 7..0
--   key(255:0)  : r = key bytes 0..15, s = key bytes 16..31
--   msg(511:0)  : message, up to 64 bytes
--   msg_len     : message length in bytes (0..64)
--   tag(127:0)  : 16-byte tag
--
-- File type in Vivado: VHDL 2008
-- ============================================================================
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity poly1305_mac is
    port (
        clk     : in  std_logic;
        rst     : in  std_logic;
        start   : in  std_logic;
        key     : in  std_logic_vector(255 downto 0);
        msg     : in  std_logic_vector(511 downto 0);
        msg_len : in  std_logic_vector(6 downto 0);
        tag     : out std_logic_vector(127 downto 0);
        done    : out std_logic
    );
end poly1305_mac;

architecture rtl of poly1305_mac is

    -- clock cycles from core input to core output (pipeline depth of Poly1305.vhd)
    constant CORE_LATENCY : natural := 20;

    type state_t is (IDLE, SETUP, WAIT_CORE, FINAL_1, FINAL_2, FINISHED);
    signal state : state_t := IDLE;

    -- The core always adds 2^128 (pad bit of a FULL block).
    -- For a last block of n bytes (n < 16) the pad bit must be 2^(8n), so the
    -- controller adds PAD_FIX(n) = p - 2^128 + 2^(8n) to the accumulator
    -- (adding p does not change the result mod p, it only keeps the value positive).
    type pad_array_t is array (0 to 15) of unsigned(130 downto 0);
    function init_pad_fix return pad_array_t is
        variable t : pad_array_t;
    begin
        for n in 0 to 15 loop
            t(n) := shift_left(to_unsigned(3, 131), 128) - 5 + shift_left(to_unsigned(1, 131), 8 * n);
        end loop;
        return t;
    end function;
    constant PAD_FIX : pad_array_t := init_pad_fix;

    -- the core expects r with byte 0 in bits 127..120 (it reverses the bytes itself)
    function byte_swap_128(a : unsigned(127 downto 0)) return unsigned is
        variable b : unsigned(127 downto 0);
    begin
        for i in 0 to 15 loop
            b(8 * i + 7 downto 8 * i) := a(127 - 8 * i downto 120 - 8 * i);
        end loop;
        return b;
    end function;

    signal key_r     : unsigned(255 downto 0) := (others => '0');
    signal msg_r     : unsigned(511 downto 0) := (others => '0');  -- shifts 16 bytes per block
    signal remaining : unsigned(6 downto 0)   := (others => '0');  -- bytes not processed yet
    signal wait_cnt  : natural range 0 to CORE_LATENCY := 0;

    signal h         : unsigned(129 downto 0) := (others => '0');  -- accumulator
    signal g         : unsigned(130 downto 0) := (others => '0');  -- h + 5 (for the final reduction)
    signal tag_r     : unsigned(127 downto 0) := (others => '0');
    signal done_r    : std_logic := '0';

    -- core connections
    signal core_acc  : unsigned(130 downto 0) := (others => '0');
    signal core_blk  : unsigned(127 downto 0) := (others => '0');
    signal core_r    : unsigned(127 downto 0);
    signal core_s    : unsigned(127 downto 0) := (others => '0');  -- not used by the core
    signal core_out  : unsigned(129 downto 0);

begin

    core_r <= byte_swap_128(key_r(127 downto 0));

    u_core : entity work.Poly1305
        port map (
            clk      => clk,
            acc      => core_acc,
            Blck     => core_blk,
            r        => core_r,
            s        => core_s,
            data_out => core_out
        );

    process (clk)
        variable blk : unsigned(127 downto 0);
    begin
        if rising_edge(clk) then
            if rst = '1' then
                state  <= IDLE;
                done_r <= '0';
            else
                case state is

                    -- wait for start, then latch the inputs
                    when IDLE | FINISHED =>
                        if start = '1' then
                            key_r     <= unsigned(key);
                            msg_r     <= unsigned(msg);
                            remaining <= unsigned(msg_len);
                            h         <= (others => '0');
                            done_r    <= '0';
                            if unsigned(msg_len) = 0 then
                                state <= FINAL_1;      -- empty message: tag = s
                            else
                                state <= SETUP;
                            end if;
                        end if;

                    -- prepare one block for the core
                    when SETUP =>
                        blk := msg_r(127 downto 0);
                        if remaining >= 16 then
                            core_acc  <= '0' & h;
                            remaining <= remaining - 16;
                        else
                            -- partial block: clear the unused bytes and fix the pad bit
                            for i in 0 to 15 loop
                                if to_unsigned(i, 7) >= remaining then
                                    blk(8 * i + 7 downto 8 * i) := (others => '0');
                                end if;
                            end loop;
                            core_acc  <= ('0' & h) + PAD_FIX(to_integer(remaining(3 downto 0)));
                            remaining <= (others => '0');
                        end if;
                        core_blk <= blk;
                        msg_r    <= shift_right(msg_r, 128);
                        wait_cnt <= 0;
                        state    <= WAIT_CORE;

                    -- core computes h = (h + block) * r mod (2^130 - 5)
                    when WAIT_CORE =>
                        if wait_cnt = CORE_LATENCY then
                            h <= core_out;
                            if remaining = 0 then
                                state <= FINAL_1;
                            else
                                state <= SETUP;
                            end if;
                        else
                            wait_cnt <= wait_cnt + 1;
                        end if;

                    -- final reduction: if h >= p then h = h - p   (h >= p  <=>  h + 5 >= 2^130)
                    when FINAL_1 =>
                        g <= ('0' & h) + 5;
                        state <= FINAL_2;

                    -- tag = (h + s) mod 2^128
                    when FINAL_2 =>
                        if g(130) = '1' then
                            tag_r <= g(127 downto 0) + key_r(255 downto 128);
                        else
                            tag_r <= h(127 downto 0) + key_r(255 downto 128);
                        end if;
                        done_r <= '1';
                        state  <= FINISHED;

                end case;
            end if;
        end if;
    end process;

    tag  <= std_logic_vector(tag_r);
    done <= done_r;

end rtl;


-- ============================================================================
-- Part 9: crypto_accel - TOP (register map + control)
-- ============================================================================
-- The CPU talks to the accelerator through 32-bit registers. In this project
-- the CPU's CFU (custom instructions, neorv32_cpu_alu_cfu.vhd) drives this
-- port, but nothing here depends on the CFU, so a memory-mapped wrapper could
-- use it the same way.
--
-- Register map (index = 8-bit register address):
--   ChaCha20 (Part 1)
--   0x00-0x07  W  key        (word 0 = key bytes 0..3, write-only)
--   0x08-0x0A  W  nonce      (word 0 = nonce bytes 0..3)
--   0x0B       W  block counter
--   0x0C       R  status     bit 0 = done, bit 1 = busy
--   0x10-0x1F  W  plaintext  (16 words = 64 bytes)
--              R  ciphertext (rvalid = 0 while ChaCha20 is busy)
--   Poly1305 (Parts 2-8)
--   0x20-0x27  W  key = r (0x20-0x23) || s (0x24-0x27), write-only
--   0x28       W  message length in bytes (0..64)
--   0x29       R  status     bit 0 = done, bit 1 = busy
--   0x2C-0x2F  R  tag        (16 bytes, rvalid = 0 while Poly1305 is busy)
--   0x30-0x3F  W  message    (16 words = 64 bytes; only the first
--                             "length" bytes are used)
--
-- ChaCha20 reads its inputs while it runs: always read the result first (the
-- read waits for it), then write the next block. Poly1305 copies its inputs
-- when it starts.
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
        -- control (1-clock pulses)
        start_chacha : in  std_logic;                      -- encrypt one block
        start_poly   : in  std_logic;                      -- compute one Poly1305 tag
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

    -- Poly1305 input registers (copied by poly1305_mac when it starts)
    signal po_key    : std_logic_vector(255 downto 0) := (others => '0');
    signal po_len    : std_logic_vector(6 downto 0)   := (others => '0');
    signal po_msg    : std_logic_vector(511 downto 0) := (others => '0');
    signal po_tag    : std_logic_vector(127 downto 0);
    signal po_done   : std_logic;
    signal po_busy   : std_logic := '0';   -- poly1305_mac has no busy output: set on start, cleared on done

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

    u_poly : entity work.poly1305_mac
        port map (
            clk     => clk,
            rst     => rst,
            start   => start_poly,
            key     => po_key,
            msg     => po_msg,
            msg_len => po_len,
            tag     => po_tag,
            done    => po_done
        );

    -- Poly1305 busy flag (done of the previous run is cleared on the start edge)
    process (clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                po_busy <= '0';
            elsif start_poly = '1' then
                po_busy <= '1';
            elsif po_done = '1' then
                po_busy <= '0';
            end if;
        end if;
    end process;

    -- register write
    process (clk)
        variable a : unsigned(5 downto 0);
    begin
        if rising_edge(clk) then
            a := unsigned(waddr(5 downto 0));
            if we = '1' and waddr(7 downto 6) = "00" then
                for k in 0 to 7 loop                           -- ChaCha20 key
                    if a = k then ch_key(32 * k + 31 downto 32 * k) <= wdata; end if;
                end loop;
                for k in 0 to 2 loop                           -- ChaCha20 nonce
                    if a = 8 + k then ch_nonce(32 * k + 31 downto 32 * k) <= wdata; end if;
                end loop;
                if a = 11 then ch_ctr <= wdata; end if;        -- ChaCha20 counter
                for k in 0 to 15 loop                          -- ChaCha20 plaintext
                    if a = 16 + k then ch_din(32 * k + 31 downto 32 * k) <= wdata; end if;
                end loop;
                for k in 0 to 7 loop                           -- Poly1305 key
                    if a = 32 + k then po_key(32 * k + 31 downto 32 * k) <= wdata; end if;
                end loop;
                if a = 40 then po_len <= wdata(6 downto 0); end if;   -- Poly1305 length
                for k in 0 to 15 loop                          -- Poly1305 message
                    if a = 48 + k then po_msg(32 * k + 31 downto 32 * k) <= wdata; end if;
                end loop;
            end if;
        end if;
    end process;

    -- register read
    process (raddr, ch_dout, ch_done, ch_busy, po_tag, po_done, po_busy)
        variable a : unsigned(5 downto 0);
    begin
        a      := unsigned(raddr(5 downto 0));
        rdata  <= (others => '0');
        rvalid <= '1';
        if raddr(7 downto 6) = "00" then
            if a = 12 then                                     -- ChaCha20 status
                rdata(0) <= ch_done;
                rdata(1) <= ch_busy;
            end if;
            for k in 0 to 15 loop                              -- ChaCha20 ciphertext
                if a = 16 + k then
                    rdata  <= ch_dout(32 * k + 31 downto 32 * k);
                    rvalid <= not ch_busy;
                end if;
            end loop;
            if a = 41 then                                     -- Poly1305 status
                rdata(0) <= po_done and not po_busy;
                rdata(1) <= po_busy;
            end if;
            for k in 0 to 3 loop                               -- Poly1305 tag
                if a = 44 + k then
                    rdata  <= po_tag(32 * k + 31 downto 32 * k);
                    rvalid <= not po_busy;
                end if;
            end loop;
        end if;
    end process;

    busy <= ch_busy or po_busy;

end rtl;
