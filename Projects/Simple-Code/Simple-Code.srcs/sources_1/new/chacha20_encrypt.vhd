library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity chacha20_encrypt is
    port (
        clk   : in  std_logic;
        rst   : in  std_logic;
        start : in  std_logic;
        done  : out std_logic
    );
end entity;

architecture rtl of chacha20_encrypt is
    type word_array_t is array (0 to 15) of unsigned(31 downto 0);

    signal done_r       : std_logic := '0';
    signal ciphertext_r : std_logic_vector(511 downto 0) := (others => '0');

    signal key       : std_logic_vector(255 downto 0) := (others => '0');
    signal nonce     : std_logic_vector(95 downto 0)  := (others => '0');
    signal counter   : std_logic_vector(31 downto 0)  := x"00000001";

    -- Plaintext = "Hello my chacha20"
    signal plaintext : std_logic_vector(511 downto 0) :=
        x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000303261686361686320796D206F6C6C6548";

    function rotl32(x : unsigned(31 downto 0); n : natural) return unsigned is
    begin
        return (x sll n) or (x srl (32 - n));
    end function;

    function get_le_word(v : std_logic_vector; start_byte : natural) return unsigned is
        variable r : unsigned(31 downto 0);
        variable b0, b1, b2, b3 : integer;
    begin
        b0 := start_byte * 8;
        b1 := (start_byte + 1) * 8;
        b2 := (start_byte + 2) * 8;
        b3 := (start_byte + 3) * 8;

        r(7 downto 0)   := unsigned(v(b0 + 7 downto b0));
        r(15 downto 8)  := unsigned(v(b1 + 7 downto b1));
        r(23 downto 16) := unsigned(v(b2 + 7 downto b2));
        r(31 downto 24) := unsigned(v(b3 + 7 downto b3));
        return r;
    end function;

begin
    process(clk, rst)
        variable s  : word_array_t;
        variable w  : word_array_t;
        variable a, b, c, d : unsigned(31 downto 0);
        variable ks : std_logic_vector(511 downto 0);
        variable ct : std_logic_vector(511 downto 0);

        procedure quarter_round(
            variable aa : inout unsigned(31 downto 0);
            variable bb : inout unsigned(31 downto 0);
            variable cc : inout unsigned(31 downto 0);
            variable dd : inout unsigned(31 downto 0)
        ) is
        begin
            aa := aa + bb;  dd := dd xor aa;  dd := rotl32(dd, 16);
            cc := cc + dd;  bb := bb xor cc;  bb := rotl32(bb, 12);
            aa := aa + bb;  dd := dd xor aa;  dd := rotl32(dd, 8);
            cc := cc + dd;  bb := bb xor cc;  bb := rotl32(bb, 7);
        end procedure;

    begin
        if rst = '1' then
            done_r       <= '0';
            ciphertext_r <= (others => '0');

        elsif rising_edge(clk) then
            done_r <= '0';

            if start = '1' then
                s(0)  := x"61707865";
                s(1)  := x"3320646E";
                s(2)  := x"79622D32";
                s(3)  := x"6B206574";

                s(4)  := get_le_word(key, 0);
                s(5)  := get_le_word(key, 4);
                s(6)  := get_le_word(key, 8);
                s(7)  := get_le_word(key, 12);
                s(8)  := get_le_word(key, 16);
                s(9)  := get_le_word(key, 20);
                s(10) := get_le_word(key, 24);
                s(11) := get_le_word(key, 28);

                s(12) := unsigned(counter);
                s(13) := get_le_word(nonce, 0);
                s(14) := get_le_word(nonce, 4);
                s(15) := get_le_word(nonce, 8);

                w := s;

                for i in 0 to 9 loop
                    a := w(0); b := w(4); c := w(8); d := w(12);
                    quarter_round(a,b,c,d);
                    w(0):=a; w(4):=b; w(8):=c; w(12):=d;

                    a := w(1); b := w(5); c := w(9); d := w(13);
                    quarter_round(a,b,c,d);
                    w(1):=a; w(5):=b; w(9):=c; w(13):=d;

                    a := w(2); b := w(6); c := w(10); d := w(14);
                    quarter_round(a,b,c,d);
                    w(2):=a; w(6):=b; w(10):=c; w(14):=d;

                    a := w(3); b := w(7); c := w(11); d := w(15);
                    quarter_round(a,b,c,d);
                    w(3):=a; w(7):=b; w(11):=c; w(15):=d;

                    a := w(0); b := w(5); c := w(10); d := w(15);
                    quarter_round(a,b,c,d);
                    w(0):=a; w(5):=b; w(10):=c; w(15):=d;

                    a := w(1); b := w(6); c := w(11); d := w(12);
                    quarter_round(a,b,c,d);
                    w(1):=a; w(6):=b; w(11):=c; w(12):=d;

                    a := w(2); b := w(7); c := w(8); d := w(13);
                    quarter_round(a,b,c,d);
                    w(2):=a; w(7):=b; w(8):=c; w(13):=d;

                    a := w(3); b := w(4); c := w(9); d := w(14);
                    quarter_round(a,b,c,d);
                    w(3):=a; w(4):=b; w(9):=c; w(14):=d;
                end loop;

                for i in 0 to 15 loop
                    w(i) := w(i) + s(i);
                end loop;

                for i in 0 to 15 loop
                    ks(i*32 + 7  downto i*32 + 0)  := std_logic_vector(w(i)(7 downto 0));
                    ks(i*32 + 15 downto i*32 + 8)  := std_logic_vector(w(i)(15 downto 8));
                    ks(i*32 + 23 downto i*32 + 16) := std_logic_vector(w(i)(23 downto 16));
                    ks(i*32 + 31 downto i*32 + 24) := std_logic_vector(w(i)(31 downto 24));
                end loop;

                ct := plaintext xor ks;
                ciphertext_r <= ct;
                done_r <= '1';
            end if;
        end if;
    end process;

    done <= done_r;
end architecture;