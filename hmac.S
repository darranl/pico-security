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

@ Stack Space
@
@ ?  words = Length of text (rounded to word boundary)
@ 16 words = K XOR IPAD
@  5 words = H ( K XOR IPAD, text)
@ 16 words = K then K XOR OPAD
@  1 word  = Address for response
@  1 word  = Length of test
@  1 word  = Address of text
@  1 word  = Length of raw key
@  1 word  = Address of raw key 
@  1 word  = size of stack (Make clean up eaiser)

.equ FIXED_STACK_SPACE, 0xAC   @ 172 Bytes

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
@   SP will be pointing to this.
@ 
@ Return Value - None (May use return to indicate error state)
.thumb_func             @ We may B to SDK code
.global hmac_sha1     @ This line says the label needs to be global.
 hmac_sha1:           @ This then defines the label.
    PUSH {R4-R5, LR}     @ Two registers needed for initial calculation.
    @ Caclulate total stack space.
    @ First calculate words needed for text i.e. length + 4 - (length % 4)
    @ where length % 4 > 0 
    MOV R4, #0x3        @ i.e. 0...00000011
    AND R4, R3, R4
    CMP R4, #0x0
    BGT calc_padding
create_stack:
    @ Do the addition
    ADD R4, R4, R3
    MOV R5, #FIXED_STACK_SPACE
    ADD R4, R4, R5
    MOV R5, SP
    SUB R5, R5, R4
    MOV SP, R5
    @ Now store the parameters into the reserved stack space.
    @ Store stack size
    @ Find and store return address
    @ Store remainder
    @ All registers (R0 - R5) free to be used as needed.

    @ TODO Free up stack space allocated.
    POP {R4-R5, PC}

@ R4 is not 0 so calculate padding needed.
@ Store the result in R4, can also use R5
calc_padding:
    MOV R5, #0x4
    SUB R4, R5, R4
    B create_stack

