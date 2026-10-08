# How to run the project: Vivado → VS Code → Tera Term

| Tool | What you do in it | File |
|---|---|---|
| **Vivado** | Make the **hardware** (CPU + ChaCha20, Poly1305, Keccak-256) and load it into the FPGA | `neorv32_test_setup_approm.bit` |
| **VS Code** | Build the **program** (C code) by typing a `make` command | `neorv32_exe.bin` |
| **Tera Term** | Send the program to the board, then read what it prints | — |

All crypto hardware is in **one VHDL file**, `hw\crypto_accel.vhd`:
- Part 1: ChaCha20
- Parts 2-8: Poly1305
- Parts 9-12: Keccak-256
- Part 13: the CPU interface

---

## 1. Vivado: load the hardware

1. Open `D:\Graduation-Project\Projects\Simple-Code\Simple-Code.xpr`.
2. *(Only after you change VHDL, or the first time on a new PC)* **Generate Bitstream**. This takes about 10 minutes.
3. Plug in the board → **Open Hardware Manager → Open Target → Auto Connect**.
4. **Program Device**, then pick the **`.bit`** file (never the `.bin`):
   `Projects\Simple-Code\Simple-Code.runs\impl_1\neorv32_test_setup_approm.bit`
   - A backup copy is in `demo\neorv32_crypto.bit`.

After unplugging the board, repeat steps 3–4 (the FPGA forgets it).

## 2. VS Code: build the program

1. Open the folder `D:\Graduation-Project`.
2. Open a terminal (**Terminal → New Terminal**) and type:
   ```
   cd neorv32-main\sw\example\demo_blink_led
   make APP=my_crypto clean exe
   ```
   - `APP=` picks the C program to build (see the table below).
   - `clean` deletes the old build files.
   - `exe` makes `neorv32_exe.bin`.
3. It worked when the last line says `Executable (EXE): ... bytes`.

| `APP=` | What it does |
|---|---|
| `my_crypto` | **Your own inputs** (edit the top of `my_crypto.c`: message up to 256 characters, AAD, key, nonce). ChaCha20-Poly1305 + Keccak-256 in SW and HW, 1000× benchmark, summary with totals |
| `demo_chacha20` | ChaCha20: official test + your typed message + benchmark |
| `demo_chacha20_poly1305` | **ChaCha20-Poly1305 (RFC 8439)**: official tests + your typed message + tamper test + benchmark |
| `demo_keccak` | Keccak-256: known values + a 300-byte message + your typed message + benchmark |
| `crypto_hw_test` | Quick hardware self-test of everything (2 s) |

## 3. Tera Term: send and run

1. **Serial**, port **COM3**. On another PC, check the number in *Device Manager → Ports*.
   - *Setup → Serial port*: 19200 baud, 8 data bits, no parity, 1 stop bit.
   - *Setup → Terminal → Receive: AUTO*.
2. Press **BTN0** on the board → press any key within 8 s.
3. Type **`u`** → **File → Send file…** → tick **Binary** → choose `neorv32_exe.bin` → wait for `OK`.
4. Type **`e`**. The program starts.

To change something: edit the C file → `make ...` again → do steps 2–4 again. Step 1 is not needed again.

**LEDs:**
- LD1 is on while the software runs, and LD2 while the hardware runs.
- At the end the RGB LED turns green (all checks passed) or red (a check failed).

## 4. What `my_crypto` prints

- **Inputs:** your message, AAD, key and nonce, as text and hex.
- **[1] Results (ChaCha20-Poly1305, RFC 8439):**
  - the ChaCha20 ciphertext (blocks 1, 2, …);
  - the Poly1305 one-time key (= ChaCha20 block 0) and the MAC input (AAD | zeros | ciphertext | zeros | lengths);
  - the Poly1305 tag;
  - the receiver's check: the tag is OK and the message comes back;
  - the Keccak-256 hash.
  - Each one is shown for software and hardware, and says `PASS` when they are equal.
- **[2] Benchmark:** a progress bar for each unit, SW then HW, 1000 runs each.
- **[3] SUMMARY:** a table of total time, cycles per run and speedup, plus a **TOTAL** row for all three units.
  - Example: `results\my_crypto_board.txt`.
- **Last line:** `ALL CHECKS PASSED`.

## 5. Copy the output from Tera Term

- **Copy:** select text with the mouse. It is copied as soon as you release the button (or use *Edit → Copy*).
- **Do not right-click in the Tera Term window.** Right-click pastes the clipboard and sends it to the board.
- **Save everything to a file:** before step 3.4, choose *File → Log…* → pick a file name → *Save*.
  Stop it with *File → Stop Logging*. Then open the `.txt` file in VS Code.

## 6. Check the results online (ChaCha20 + Keccak links tested 2026-10-08; the board also matches an independent Python reference)

**Why hex?** The ciphertext, tag and hash are random bytes, not letters. So the board and the websites both write them in hex (2 characters per byte).
- "Same result" means the **same hex characters**.
- Only **decrypting** turns the ciphertext back into your message.

Long results are printed over 2 lines. Join them into one line (no spaces) before pasting.

The ready links below use the default values in `my_crypto.c`. If you change the message or key, change the same fields on the page.

### ChaCha20: CyberChef (gchq.github.io/CyberChef)

- [Encrypt (ready link)](https://gchq.github.io/CyberChef/#recipe=ChaCha(%7B'option':'UTF8','string':'my%2032-byte%20secret%20key%204%20ChaCha20'%7D,%7B'option':'UTF8','string':'unique%20nonce'%7D,1,'20','Raw','Raw')To_Hex('None',0)&input=SGVsbG8gZnJvbSBvdXIgUklTQy1WIGNyeXB0byBhY2NlbGVyYXRvciE):
  type the message. The output must equal the board's ciphertext (`9a7eddaf…88f722`).
- [Decrypt (ready link)](https://gchq.github.io/CyberChef/#recipe=ChaCha(%7B'option':'UTF8','string':'my%2032-byte%20secret%20key%204%20ChaCha20'%7D,%7B'option':'UTF8','string':'unique%20nonce'%7D,1,'20','Hex','Raw')&input=OWE3ZWRkYWY1ODBmM2JlZTQxYTAyMzcxNzc5MTMwZTcyNDg4YTA4ODcxYWUwNDU3MGFlNjg4NzIzMzg0NTk2YjBmNTJmMDE1ODZjMjg4ZjcyMg):
  paste the board's ciphertext hex. Your message comes back as text.

To set it up by hand, use the operation **ChaCha** with these fields:

| Field | `my_crypto` | `demo_chacha20`, `demo_chacha20_poly1305` |
|---|---|---|
| Key (the secret) | `my 32-byte secret key 4 ChaCha20`, dropdown **UTF8** | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`, dropdown **Hex** |
| Nonce (number used once) | `unique nonce`, dropdown **UTF8** | `000000000000004a00000000`, dropdown **Hex** |
| Counter | `1` (CyberChef starts at 0, so change it) | `1` |
| Rounds | `20` | `20` |

- **Encrypt:** set Input = Raw and Output = Raw, then add the operation **To Hex** with Delimiter = None. Without To Hex, the bytes are shown with spaces (`9a 7e dd …`).
- **Decrypt:** set Input = Hex and Output = Raw.
- Don't use devglan: it uses a different ChaCha20 variant.

### Keccak-256: CyberChef

- [Keccak 256 (ready link)](https://gchq.github.io/CyberChef/#recipe=Keccak('256')&input=SGVsbG8gZnJvbSBvdXIgUklTQy1WIGNyeXB0byBhY2NlbGVyYXRvciE):
  type the message. The output must equal the board's hash (`b36c4659…3c293378`).
- By hand: operation **Keccak**, Size **256**. Don't pick "SHA3", which gives a different hash.
- Example: "test" gives `9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658`.

### Poly1305: javainuse.com/poly1305mac

CyberChef has no Poly1305. In ChaCha20-Poly1305 the board prints the two things Poly1305 needs. Use the "Generate MAC" box on javainuse:

| Field | What to type |
|---|---|
| 32-byte Key (Hex) | the **Poly1305 one-time key** line (default: `6d839942b5badf7e9a29168e9fc7c261eb0a10e3d2f159cb636f168d9c9400c6`) |
| Message | the **Poly1305 MAC input** hex (all its lines joined) |
| Input Format | **Hexadecimal** |

The MAC must equal the board's tag (default: `9be6653dbe0a60a59960267bb226291a`).
- If you want to test the website itself first, use the official RFC 8439 example:
  - key `85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b`
  - message `Cryptographic Forum Research Group` (UTF-8)
  - the tag must be `a8061dc1305136c6c22b8baf0c0127a9`

### ChaCha20-Poly1305 all at once: lddgo.net/en/encrypt/chacha20-encrypt-decrypt (not tested by me yet)

- Algorithm **ChaCha20Poly1305**.
- Password = `MY_KEY` and Nonce = `MY_NONCE` (format "string"); AAD = `MY_AAD`; Output format **hex**.
- The output should be the ciphertext followed by the 16-byte tag.
- Test the site first with the official RFC 8439 2.8.2 example (it is in `demo_chacha20_poly1305`, part 1b):
  - key hex `808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f`
  - nonce hex `070000004041424344454647`
  - AAD hex `50515253c0c1c2c3c4c5c6c7`
  - message "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  - the result must start `d31a8d34…` and the tag must be `1ae10b594f09e26a7e902ecbd0600691`.

## 7. Optional: watch the hardware in the Vivado simulator

In Vivado: **Run Simulation → Run Behavioral Simulation**.
- The waveform shows the ChaCha20, Poly1305 and Keccak signals.
- The Tcl Console says `ALL TESTS PASSED`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No text after BTN0 | Check COM3 / 19200 baud; program the FPGA again (step 1.3–1.4) |
| `Custom crypto instructions (CFU): NO` | Old bitstream: program the `.bit` again (step 1) |
| `ERROR_CHECKSUM` on upload | Send the file again with **Binary** ticked |
| `make: command not found` | Open a new VS Code terminal |
| Upload stops with an error (program too big) | The FPGA still has an old bitstream with 16 KB program memory: program the new `.bit` (step 1) |
| Build error `MY_KEY must be exactly 32 characters` | Key 32, nonce 12, message 1..64 characters |
