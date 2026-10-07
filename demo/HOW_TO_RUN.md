# How to run the demos

Everything for a demo is in this folder:

| File | What it is |
|---|---|
| `neorv32_crypto.bit` | FPGA bitstream: RISC-V CPU + ChaCha20/Poly1305/Keccak hardware |
| `demo_chacha20.bin` | Demo 1: ChaCha20 encryption, software vs hardware |
| `demo_chacha20_poly1305.bin` | Demo 2: ChaCha20 + Poly1305 (encrypt + authenticate) |
| `demo_keccak.bin` | Demo 3: SHA3-256 hashing, software vs hardware |
| `crypto_hw_test.bin` | Quick self-test of all hardware units (about 2 s) |
| `build_demos.bat` | Rebuilds the `.bin` files after a C change |

Every demo runs these steps live on the board:
1. **Official test**: the RFC/NIST example is computed in software and in hardware and compared with the published answer.
2. **Your message**: type a message (or wait 20 s for the default one). Each demo does something different with it:
   - Demo 1 encrypts and decrypts it.
   - Demo 2 makes a tag, then changes 1 bit to show the change is **rejected**.
   - Demo 3 hashes it, then changes 1 bit to show about half of the hash changes.
3. **Benchmark**: 1000 runs in software, then 1000 in hardware, with live progress bars. Then every run is checked: software == hardware.
4. **Results**: time (hardware 1 µs counter), cycles, and the speedup.

**LEDs:**
- LD1 is on while the software runs, and LD2 is on while the hardware runs.
- At the end the RGB LED turns **green** if all checks passed and **red** if any failed.

Demo 3 takes about 1 minute, because the Keccak software is slow on this small CPU.

---

## Step 0: load the FPGA (once after every power-up), in Vivado

1. Plug in the Cmod A7 (USB).
2. In Vivado, choose **Open Hardware Manager → Open Target → Auto Connect**.
3. Choose **Program Device**, set the bitstream file to `demo\neorv32_crypto.bit` (leave the probes file empty), and click **Program**.

The FPGA forgets this when the power is off, so repeat it after every power-up.

## A) Tera Term

1. **Setup → Serial port:** COM3, 19200 baud, 8 data bits, no parity, 1 stop bit, no flow control.
2. **Setup → Terminal → New-line → Receive: AUTO** (or LF), so the progress bars redraw on one line.
3. Press **BTN0** (reset) on the board. The bootloader prints `Auto-boot in 8s. Press any key to abort.` Press any key **within 8 seconds**.
4. Type **`u`**. It answers `Awaiting neorv32_exe.bin...`.
5. Choose **File → Send file…**, tick **Binary**, and pick a demo, for example `demo\demo_keccak.bin`. Wait for `OK`.
6. Type **`e`**. The demo starts. Type your message when it asks and press Enter.
7. To run it again, press Enter. To run another demo, press BTN0 and repeat from step 3.

## B) VS Code

1. Open the folder `D:\Graduation-Project` in VS Code.
2. **Close Tera Term**, because only one program can use COM3.
3. Choose **Terminal → Run Task…** and pick one of these:
   - `Demo 1: ChaCha20 - upload & run`
   - `Demo 2: ChaCha20 + Poly1305 - upload & run`
   - `Demo 3: Keccak SHA3-256 - upload & run`
   - `Hardware self-test (all units) - upload & run`
4. Press **BTN0** on the board. The task uploads the program and starts it.
5. Everything appears in the VS Code terminal. Click into the terminal and type your message when asked. Press **Esc** to stop.

Other tasks:
- `Build demo programs` rebuilds the `.bin` files after a C change.
- `Simulate crypto cores` runs the VHDL testbench and takes a few seconds.
- `Simulate whole CPU + crypto` runs the full-system simulation and takes about 15 minutes.

The same thing without VS Code, from a terminal in `D:\Graduation-Project`:
```
powershell -ExecutionPolicy Bypass -File hw\upload.ps1 -Exe demo\demo_keccak.bin -Interactive
```

## C) Vivado: watch the hardware working (simulation waveform)

1. Open `Projects\Simple-Code\Simple-Code.xpr`.
2. Choose **Flow Navigator → Simulation → Run Simulation → Run Behavioral Simulation**.

The simulation top is `tb_crypto_accel`, and `hw\waves_crypto.tcl` loads automatically. When you run it:
- The waveform window opens with the signals grouped: **ChaCha20 / Poly1305 / Keccak**.
- The Tcl Console shows the PASS lines and `ALL TESTS PASSED` (19 tests).

To watch one block being computed, zoom in on a `start` pulse:
- **ChaCha20:** `rnd` counts 0 → 9 (one double round per clock), then `done` = 1, which is 10 cycles.
- **Poly1305:** `state` goes SETUP → WAIT_CORE for each 16-byte block, then FINAL. A 64-byte message takes 90 cycles.
- **Keccak:** `round_cnt` counts 0 → 23 (one round per clock), then `done` = 1, which is 24 cycles.
- The inputs (`key`, `data_in`, `ke_msg`, …) and outputs (`data_out`, `po_tag`, `ke_digest`) are shown in hex.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No bootloader text after BTN0 | Check the COM port / 19200 baud; program the FPGA again (Step 0) |
| `Access to the port 'COM3' is denied` (VS Code / script) | Close Tera Term |
| Demo prints `Custom crypto instructions (CFU): NO` | The board has an old bitstream: do Step 0 with `demo\neorv32_crypto.bit` |
| Upload says `ERROR_CHECKSUM` | Send the file again with **Binary** ticked |
| Changed C code but the board runs the old version | Run `build_demos.bat` (not while Vivado is building), then upload again |
