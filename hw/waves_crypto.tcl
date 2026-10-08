# ===========================================================================
# waves_crypto.tcl - waveform view for tb_crypto_accel in the Vivado simulator
#
# Vivado runs this automatically for "Run Simulation > Run Behavioral Simulation"
# (simulation top = tb_crypto_accel, custom Tcl = this file). It adds the
# important signals of the three crypto cores in groups and runs the whole
# testbench (about 1 ms of simulated time). The PASS/FAIL lines appear in the
# Tcl Console. Zoom in on a "start" pulse to watch one block being computed:
#   ChaCha20: rnd counts 0..9 (one double round per clock), then done = 1
#   Poly1305: state SETUP -> WAIT_CORE (wait_cnt 0..20) per 16-byte block -> FINAL
#   Keccak:   round_cnt counts 0..23 (one round per clock), then done = 1
# Long messages (near the end): init = 1 only on the first piece/block,
#   final = 1 only on the last one; h / the Keccak state is kept in between
# ===========================================================================
add_wave_divider {Clock / reset}
add_wave {{/tb_crypto_accel/clk}} {{/tb_crypto_accel/rst}}

add_wave_divider {ChaCha20 - 10 double rounds per 64-byte block}
add_wave {{/tb_crypto_accel/start}} {{/tb_crypto_accel/busy}} {{/tb_crypto_accel/done}}
add_wave -radix unsigned {{/tb_crypto_accel/dut/rnd}}
add_wave -radix hex {{/tb_crypto_accel/dut/x}}
add_wave -radix hex {{/tb_crypto_accel/key}} {{/tb_crypto_accel/counter}} {{/tb_crypto_accel/data_in}} {{/tb_crypto_accel/data_out}}

add_wave_divider {Poly1305 - one 16-byte block per pass through the multiplier}
add_wave {{/tb_crypto_accel/po_start}} {{/tb_crypto_accel/po_init}} {{/tb_crypto_accel/po_final}} {{/tb_crypto_accel/po_done}}
add_wave {{/tb_crypto_accel/dut_poly/state}}
add_wave -radix unsigned {{/tb_crypto_accel/po_len}} {{/tb_crypto_accel/dut_poly/remaining}} {{/tb_crypto_accel/dut_poly/wait_cnt}}
add_wave -radix hex {{/tb_crypto_accel/dut_poly/h}} {{/tb_crypto_accel/po_tag}}

add_wave_divider {Keccak-256 - 24 rounds, one per clock}
add_wave {{/tb_crypto_accel/ke_start}} {{/tb_crypto_accel/ke_init}} {{/tb_crypto_accel/ke_final}} {{/tb_crypto_accel/ke_done}}
add_wave {{/tb_crypto_accel/dut_keccak/fsm}}
add_wave -radix unsigned {{/tb_crypto_accel/ke_len}} {{/tb_crypto_accel/dut_keccak/round_cnt}}
add_wave -radix hex {{/tb_crypto_accel/ke_msg}} {{/tb_crypto_accel/ke_digest}}

run all
