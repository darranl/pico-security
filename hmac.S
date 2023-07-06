@ Copyright 2023, Darran A Lofthouse
@
@ This file is part of pico-security.
@
@ pico-security is free software: you can redistribute it and/or modify it under the terms 
@ of the GNU General Public License as published by the Free Software Foundation, either 
@ version 3 of the License, or (at your option) any later version.
@
@ pico-security is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
@ without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
@ See the GNU General Public License for more details.
@
@ You should have received a copy of the GNU General Public License along with pico-security.
@ If  not, see <https://www.gnu.org/licenses/>. 


@ Start Function:
@  extern void hmac_sha1(char *key, uint32_t key_length, char *text, uint32_t text_length, uint32_t *mac);
@
@ Initial Registers
@   R0 - Pointer to first char/byte of the key.
@   R1 - Length of the key.
@   R2 - Pointer to first char/byte of the text.
@   R3 - Length of the text.
@
@ On the stack:
@   Pointer to address to hold 160 bit (20 bytes or 5 words) MAC.
@ Intermediate Registers
@ 
@ Return Value - None (May use return to indicate error state)
.thumb_func             @ We may B to SDK code
.global hmac_sha1     @ This line says the label needs to be global.
 hmac_sha1:           @ This then defines the label.

    BX LR