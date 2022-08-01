#!/bin/bash

VHT_MPS3_Corstone_SSE-300 \
-C mps3_board.visualisation.disable-visualisation=1 \
-C mps3_board.telnetterminal0.start_telnet=0 \
-C mps3_board.uart0.out_file=- \
-a Objects/image.axf
