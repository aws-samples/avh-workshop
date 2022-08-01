Board: ARM AVH_MPS3_Corstone-300
----------------------------------------------

MPS3 platform for Corstone-300 simulated by Arm Virtual Hardware Targets (VHT).

Running the VHT in uVision requires the following settings:
 - open "Options for Target"
 - select "Debug" tab
 - under "Use" select "Models ARMv8-M Debugger" and click "Settings" end enter the following:
   - Command: $KARM\VHT\VHT_MPS3_Corstone_SSE-300_MDK.exe
   - Target: cpu0
   - Configuration File: fvp_config.txt

Running the VHT via command line (from project root directory and VHT executable in path):
`VHT_MPS3_Corstone_SSE-300_MDK -f fvp_config.txt -C mps3_board.visualisation.disable-visualisation=1 -C mps3_board.telnetterminal0.start_telnet=0 -C mps3_board.uart0.out_file=- -a <image>`

The heap/stack setup and the CMSIS-Driver assignment is in configuration files of related software components.

### System Configuration

| System Component        | Setting
|:------------------------|:----------------------------------------
| Device                  | SSE-3000-MPS3
| Clock                   | 32 MHz
| Heap                    | 64 kB (configured in region_limit.h file)
| Stack (MSP)             | 1 kB (configured in region_limit.h file)

**STDIO** is routed to USART0

### CMSIS-Driver mapping

| CMSIS-Driver | Peripheral
|:-------------|:----------
| ETH_MAC0     | Ethernet LAN91C111
| ETH_PHY0     | Ethernet LAN91C111
| USART0       | USART0

| CMSIS-Driver VIO  | Physical board hardware
|:------------------|:-----------------------
| vioBUTTON0        | User Button PB1
| vioBUTTON1        | User Button PB2
| vioLED0           | User LED UL0
| vioLED1           | User LED UL1
| vioLED2           | User LED UL2
| vioLED3           | User LED UL3
| vioLED4           | User LED UL4
| vioLED5           | User LED UL5
| vioLED6           | User LED UL6
| vioLED7           | User LED UL7
