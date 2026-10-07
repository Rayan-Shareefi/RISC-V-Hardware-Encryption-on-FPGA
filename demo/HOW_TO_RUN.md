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
2. *(Only after you change VHDL)* **Generate Bitstream**. This takes about 10 minutes.
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
| `my_crypto` | **Your own inputs** (edit the top of `my_crypto.c`). Checks all 3 units, runs 1000× SW vs HW, then prints a summary with totals |
| `demo_chacha20` | ChaCha20: official test + your typed message + benchmark |
| `demo_chacha20_poly1305` | Encrypt + MAC + tamper test + benchmark |
| `demo_keccak` | Keccak-256: known values + your typed message + benchmark |
| `crypto_hw_test` | Quick hardware self-test (2 s) |

## 3. Tera Term: send and run

1. **Serial**, port **COM3**.
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

- **Inputs:** your message, keys and nonce, as text and hex.
- **[1] Results:** ChaCha20 ciphertext, Poly1305 tag and Keccak-256 hash, for software and for hardware.
  Each one says `PASS` when software = hardware.
- **[2] Benchmark:** a progress bar for each unit, SW then HW, 1000 runs each.
- **[3] SUMMARY:** a table of total time, cycles per run and speedup, plus a **TOTAL** row for all three units.
  - Example: `results\my_crypto_board.txt`.
- **Last line:** `ALL CHECKS PASSED`.

## 5. Copy the output from Tera Term

- **Copy:** select text with the mouse. It is copied as soon as you release the button (or use *Edit → Copy*).
- **Do not right-click in the Tera Term window.** Right-click pastes the clipboard and sends it to the board.
- **Save everything to a file:** before step 3.4, choose *File → Log…* → pick a file name → *Save*.
  Stop it with *File → Stop Logging*. Then open the `.txt` file in VS Code.

## 6. Check the results online

Hex is just how bytes are written: 2 digits per byte. Encrypted data looks random; that is normal.
Long results are printed over 2 lines. Join them into one line (no spaces) before pasting.

**ChaCha20:** use CyberChef (gchq.github.io/CyberChef), operation **ChaCha**, Rounds 20.

| Field | `my_crypto` | `demo_chacha20` / `demo_chacha20_poly1305` |
|---|---|---|
| Key | UTF8: the `MY_KEY` text | Hex `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| Nonce | UTF8: the `MY_NONCE` text | Hex `000000000000004a00000000` |
| Counter | `MY_COUNTER` (1) | **1** (CyberChef starts at 0, so change it) |

- **Encrypt:** Input Raw, Output Hex, type the message. The result must equal the board's ciphertext.
- **Decrypt:** Input **Hex**, Output **Raw**, paste the board's ciphertext. Your message comes back.
- Don't use devglan: it uses a different ChaCha20 variant.

**Keccak-256:** use emn178.github.io/online-tools/keccak_256.html. Type the same message.
- Example: "test" gives `9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658`.

**Poly1305:** there is no common online tool. The program checks it in two ways:
- software = hardware;
- `demo_chacha20_poly1305` also checks the official RFC 8439 test.

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
| Build error `MY_KEY must be exactly 32 characters` | Key 32, nonce 12, message 1..64 characters |
