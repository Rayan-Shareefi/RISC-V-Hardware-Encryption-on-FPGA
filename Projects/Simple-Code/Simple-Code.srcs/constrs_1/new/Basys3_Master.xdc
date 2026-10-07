## ============================================================================
## MASTER CONSTRAINTS FILE FOR DIGILENT CMOD A7-35T (3-LED CONFIG)
## ============================================================================

## 1. System Clock (12 MHz Oscillator)
set_property PACKAGE_PIN L17 [get_ports clk_i]							
set_property IOSTANDARD LVCMOS33 [get_ports clk_i]
create_clock -add -name sys_clk_pin -period 83.33 -waveform {0 41.66} [get_ports clk_i]

## 2. Standard Green LEDs (LD1 and LD2)
# LD1 mapped to Bit 0
set_property PACKAGE_PIN A17 [get_ports {gpio_o[0]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[0]}]
# LD2 mapped to Bit 1
set_property PACKAGE_PIN C16 [get_ports {gpio_o[1]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[1]}]

## 3. The RGB LED (LD3 / Your "LD0")
# Blue Channel mapped to Bit 2 (This is your 3rd simple LED)
set_property PACKAGE_PIN B17 [get_ports {gpio_o[2]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[2]}]

# Red Channel mapped to Bit 3 (We will use C code to keep this OFF)
set_property PACKAGE_PIN C17 [get_ports {gpio_o[3]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[3]}]

# Green Channel mapped to Bit 4 (We will use C code to keep this OFF)
set_property PACKAGE_PIN B16 [get_ports {gpio_o[4]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[4]}]

## 4. Reset Button (BTN0)
set_property PACKAGE_PIN A18 [get_ports rstn_i]						
set_property IOSTANDARD LVCMOS33 [get_ports rstn_i]
set_property PULLDOWN true [get_ports rstn_i]

## 5. Remaining GPIO Bits (To satisfy 8-bit requirement)
# We move these to unused physical pins to avoid conflicts
set_property PACKAGE_PIN A16 [get_ports {gpio_o[5]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[5]}]
set_property PACKAGE_PIN K3 [get_ports {gpio_o[6]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[6]}]
set_property PACKAGE_PIN C15 [get_ports {gpio_o[7]}]					
set_property IOSTANDARD LVCMOS33 [get_ports {gpio_o[7]}]

## USB-UART Interface
set_property PACKAGE_PIN J18 [get_ports uart0_txd_o]					
set_property IOSTANDARD LVCMOS33 [get_ports uart0_txd_o]
set_property PACKAGE_PIN J17 [get_ports uart0_rxd_i]					
set_property IOSTANDARD LVCMOS33 [get_ports uart0_rxd_i]