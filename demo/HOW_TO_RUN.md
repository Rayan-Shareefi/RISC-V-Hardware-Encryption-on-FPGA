# How to run the project yourself: Vivado → VS Code → Tera Term

You work with **two files**:

| File | You make it with | It goes to | What it is |
|---|---|---|---|
| **`neorv32_test_setup_approm.bit`** (bitstream) | **Vivado** (Generate Bitstream) | Vivado → *Program Device* | The **hardware**: the RISC-V CPU + the ChaCha20, Poly1305 and Keccak circuits |
| **`neorv32_exe.bin`** (program) | **VS Code** (you type a `make` command) | **Tera Term** → bootloader | The **software**: the C program the CPU runs |

This is the same as your old counter test (counter = 0..7): Vivado loads the hardware, then the
program file you built is sent with Tera Term, and the output appears in Tera Term.

Vivado's *Program Device* window also lists `.bin` files. `neorv32_exe.bin` is **not** a bitstream:
in Vivado always pick the **`.bit`**.

All the crypto hardware is in **one VHDL file: `hw\crypto_accel.vhd`**. It holds:
- Part 1: ChaCha20
- Parts 2-8: Poly1305
- Parts 9-12: Keccak-256
- Part 13: the register interface used by the CPU's custom instructions

The Vivado project uses this file.

---

## 1. Vivado: make the hardware and load it into the FPGA

1. Open Vivado → open `D:\Graduation-Project\Projects\Simple-Code\Simple-Code.xpr`.
2. Flow Navigator → **PROGRAM AND DEBUG → Generate Bitstream**.
   - This runs synthesis + implementation by itself and takes about 8–10 minutes.
   - Wait for *Bitstream Generation successfully completed*.
3. Plug in the Cmod A7. Flow Navigator → **Open Hardware Manager → Open Target → Auto Connect**.
4. **Program Device** → *Bitstream file*:
   `D:\Graduation-Project\Projects\Simple-Code\Simple-Code.runs\impl_1\neorv32_test_setup_approm.bit` → **Program**.

The FPGA forgets the bitstream when it loses power. After unplugging, repeat step 3–4 (no need to generate it again).
`demo\neorv32_crypto.bit` is a backup copy of the same bitstream, in case you need it quickly.

## 2. VS Code: build the program file (`neorv32_exe.bin`)

1. VS Code → **File → Open Folder** → `D:\Graduation-Project`.
2. Choose the program. Each one is a C file in `neorv32-main\sw\example\demo_blink_led\`:

   | Program (`APP=`) | What it does on the board |
   |---|---|
   | `my_crypto` | **Your own values**: edit `my_crypto.c` (message, ChaCha20 key/nonce/counter, Poly1305 key), runs ChaCha20 + Poly1305 + Keccak-256 once in SW and HW |
   | `demo_chacha20` | ChaCha20: official test, your typed message, 1000-block SW vs HW benchmark |
   | `demo_chacha20_poly1305` | Encrypt + MAC, tamper test, 1000-run SW vs HW benchmark |
   | `demo_keccak` | Keccak-256: known values, your typed message, 1000-hash SW vs HW benchmark |
   | `crypto_hw_test` | Quick self-test of all hardware units (about 2 s) |

3. **Terminal → New Terminal**, then type:
   ```
   cd neorv32-main\sw\example\demo_blink_led
   make APP=my_crypto clean exe
   ```
   What the words mean:
   - `make` runs the build rules in the `makefile`.
   - `APP=my_crypto` chooses which C program to build (any name from the table).
   - `clean` deletes the old build files.
   - `exe` compiles the program and makes **`neorv32_exe.bin`**, the file for the bootloader.

   It works when the last line looks like `Executable (EXE): 13056 bytes @ 0x00000000 ...`.
   The file is now `neorv32-main\sw\example\demo_blink_led\neorv32_exe.bin`.

## 3. Tera Term: send the program and run it

1. Tera Term → **Serial**, port **COM3** → *Setup → Serial port*: 19200 baud, 8 data bits, no parity, 1 stop bit, no flow control.
   *Setup → Terminal → New-line → Receive: AUTO*, so the progress bars stay on one line.
2. Press **BTN0** (reset) on the board. The bootloader prints `Auto-boot in 8s. Press any key to abort.` → press any key (within 8 s).
3. Type **`u`**. It answers `Awaiting neorv32_exe.bin...`.
4. **File → Send file…** → tick **Binary** → choose `neorv32_exe.bin` (from step 2) → wait for `OK`.
5. Type **`e`**. The program starts. When it asks, type a message and press Enter.

To change something: edit the C file → `make APP=... clean exe` again → BTN0 → steps 2–5 again.

**LEDs:**
- LD1 is on while the software runs, and LD2 is on while the hardware runs.
- At the end the RGB LED turns green if all checks passed and red if any failed.

## 4. Check the results online yourself

The programs print every input and result in **hex**. Hex is simply how bytes are written: each byte is 2 hex digits (00–ff).
- Encrypted data and hashes look random on purpose, so turning them into text gives unreadable characters.
- That is correct. Only **decrypting** with the same key, nonce and counter gives the text back.

**ChaCha20, with CyberChef** (gchq.github.io/CyberChef), operation **"ChaCha"**. Rounds: 20.

| Field | `demo_chacha20`, `demo_chacha20_poly1305` | `my_crypto` |
|---|---|---|
| Key | Hex `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` | UTF8: the `MY_KEY` text |
| Nonce | Hex `000000000000004a00000000` | UTF8: the `MY_NONCE` text |
| Counter | **1** (CyberChef starts at 0!) | `MY_COUNTER` |

- **Encrypt:** set Input = Raw and Output = Hex, then type the message. The result must equal the board's ciphertext.
- **Decrypt:** set Input = **Hex** and Output = **Raw**, then paste the board's ciphertext hex. The original message comes back.
- Example from the demos: "Hello ChaCha20" gives `6a2a3d9f2f3b9a894e9d4f0e8a53`.
- Some other sites (for example devglan) use a different ChaCha20 variant and give different numbers. Use CyberChef.

**Keccak-256:** emn178.github.io/online-tools/keccak_256.html. Type the same message; it must equal the board's Keccak-256 line.
Example: "test" gives `9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658`.

**Why not SHA3-256?**
- SHA3-256 (the NIST standard) is the same Keccak, but with padding byte 0x06 instead of 0x01, so its hash is different.
- The project uses **Keccak-256**: `PAD_BYTE` in `hw\crypto_accel.vhd` Part 12, and `KECCAK_PAD` in `keccak_sw.c`.

## 5. Optional: watch the hardware in the Vivado simulator

In Vivado: **Run Simulation → Run Behavioral Simulation**.
- The waveform opens with ChaCha20 / Poly1305 / Keccak signal groups, and the Tcl Console shows `ALL TESTS PASSED`.
- Zoom in on a `start` pulse: ChaCha20's `rnd` counts 0..9, and Keccak's `round_cnt` counts 0..23 (one round per clock).

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No bootloader text after BTN0 | Check COM3 / 19200 baud; program the FPGA again (step 1.3–1.4) |
| Program prints `Custom crypto instructions (CFU): NO` | Old bitstream on the board: program the new `.bit` (step 1) |
| Upload says `ERROR_CHECKSUM` | Send the file again with **Binary** ticked |
| `make: command not found` | Open a new VS Code terminal (the RISC-V tools and make must be on PATH) |
| Build error `MY_KEY must be exactly 32 characters` | Fix the length in `my_crypto.c` (key 32, nonce 12, message 1..64 characters) |
