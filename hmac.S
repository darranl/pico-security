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

#include "hmac-debug.h"

@ Stack Space:
@
@ 0x9C   ?  words = Length of text (bytes rounded to word boundary)
@ 0x5C  16 words = K XOR IPAD (IPadded Key)
@ 0x48   5 words = H ( K XOR IPAD, text) (Intermedate Hash)
@ 0x08  16 words = K then K XOR OPAD
@ 0x04   1 word  = Length of text 
@ 0x00   1 word  = Post PUSH SP

.equ FIXED_STACK_SPACE, 0x9C   @ 156 Bytes

.equ TEXT_START_OFFSET, 0x9C @ 156 bytes
.equ IPADDED_KEY_OFFSET, 0x5C
.equ INTERMEDIATE_HASH_OFFSET, 0x48
.equ RAW_KEY_OFFSET, 0x08 @ 8 bytes
.equ TEXT_LENGTH_OFFSET, 0x04 
.equ POST_POP_OFFSET, 0x00

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
    BGT calc_padding  @ R4 is not 0 so calculate padding needed.
create_stack:
    @ Do the addition
    ADD R4, R4, R3
    MOV R5, #FIXED_STACK_SPACE
    ADD R4, R4, R5
    MOV R5, SP
    SUB R5, R5, R4
    MOV R4, SP      @ Regrab the current stack pointer so we can cache it.
    MOV SP, R5
    @ Store the post push SP at SP + 0x00 i.e. SP
    STR R4, [SP, #0x0]
    @ Store the length of the text to the stack.
    STR R3, [SP, #TEXT_LENGTH_OFFSET]
    @ Store the text to the stack.
    MOV R4, SP     
    MOV R5, #TEXT_START_OFFSET
    ADD R4, R4, R5             @ R4 now first address to copy text to.

    @ Check length is greater than 0
    CMP R3, #0x00
    BLS text_copy_complete    @ Less than or equal to 0 bytes to copy
copy_text_byte:
    LDRB R5, [R2]    @ Transfer one byte at a time so order is preserved.
    STRB R5, [R4]
    ADD R2, R2, #0x1
    ADD R4, R4, #0x1
    SUB R3, R3, #0x1
    BNE copy_text_byte   @ Length has not hit 0 go again.
text_copy_complete:    
    @ Just R0 and R1 in use describing the key, process the key onto the stack
    @ Set R2 to destination for key, we can use it if we need to hash the key.
    MOV R2, #RAW_KEY_OFFSET
    ADD R2, R2, SP
    CMP R1, #0x40   @ 64 bytes
    BGT hash_the_key  @ Will borrow R4 and R5
    MOV R3, #0x40    @ 64 bytes, will be used to count down how many bytes to go.    
copy_key_byte:
    @ R4 Temporariy hold value being copied/
    LDRB R4, [R0]    @ Copy key byte at a time to preserve order.
    STRB R4, [R2]
    SUB R3, #0x01 @ Adjust counter of total bytes to process first.
    BEQ key_copy_complete @ Hit 0 64 bytes copied, end key copying. (We know not bigger than this.)
    ADD R0, #0x01
    ADD R2, #0x01
    SUB R1, #0x01 @ Finally subtract from byes in key so we can check if we are at the end. 
    BNE copy_key_byte
    @ Entering key_padding:
    @  R2 - Address of next destination byte.
    @  R3 - bytes still to pad.   
key_padding: 
    MOV R4, #0x00 @ Store contant 0 in R4 as we wll use to pad the key.
pad_key_byte:
    STRB R4, [R2]
    ADD R2, #0x01
    SUB R3, #0x01 @ Adjust counter of total bytes to process.
    BNE pad_key_byte @ Not at 0, more bytes to pad.
key_copy_complete:
    @ All registers (R0 - R5) free to be used as needed.

    #ifdef LOG_DATA
    LDR R1, [SP, #TEXT_LENGTH_OFFSET]
    ADD R1, R1, #0x9C  @ This is the total length of stack we allocated
    MOV R0, SP
    BL log_data  @ All data is copied, key is copied or hashed and padded.
    #endif
    
    @ Create Key XOR IPAD
    MOV R0, SP     @ Set up source address
    ADD R0, R0, #RAW_KEY_OFFSET
    MOV R1, SP     @ Set up destination address
    ADD R1, R1, #IPADDED_KEY_OFFSET
    LDR R2, ipad   @ Load the IPAD mask into R2
    BL xor_key     @ Function call (i.e. R0-R3 may be modified)
    @ All registers (R0 - R5) free to be used as needed.

    #ifdef LOG_DATA
    LDR R1, [SP, #TEXT_LENGTH_OFFSET]
    ADD R1, R1, #0x9C  @ This is the total length of stack we allocated
    MOV R0, SP
    BL log_data @ iPad applied
    #endif

    @ Call SHA-1
    @ R0 - First byte of data
    MOV R0, SP
    ADD R0, R0, #IPADDED_KEY_OFFSET
    @ R1 - Number of bytes of data
    LDR R1, [SP, #TEXT_LENGTH_OFFSET]
    ADD R1, R1, #0x40  @ Add the 16 words (64 bytes) of the key
    @ R2 - Destination
    MOV R2, SP
    ADD R2, R2, #INTERMEDIATE_HASH_OFFSET
    BL sha1_digest
    @ All registers (R0 - R5) free to be used as needed.

    @ SHA-1 stored hash using 32bit words, we need bytes in correct order
    @ for ongoing hashes.
    MOV R2, SP
    ADD R2, R2, #INTERMEDIATE_HASH_OFFSET
    MOV R1, #0x5   @ 5 words to reverse
reverse_word:
    LDR R0, [R2]
    REV R0, R0
    STR R0, [R2]
    ADD R2, R2, #0x4
    SUB R1, R1, #0x1
    BNE reverse_word
    @ Note: We don't need to reverse the next hash as the caller is expecting
    @ 32-bit ints as the result.
    @ All registers (R0 - R5) free to be used as needed.

    #ifdef LOG_DATA
    LDR R1, [SP, #TEXT_LENGTH_OFFSET]
    ADD R1, R1, #0x9C  @ This is the total length of stack we allocated
    MOV R0, SP
    BL log_data @ Frst hash complete
    #endif

    @ Create Key XOR OPAD
    MOV R0, SP     @ Set up source address
    ADD R0, R0, #RAW_KEY_OFFSET
    MOV R1, R0     @ Set up destination address (Same as source)
    LDR R2, opad   @ Load the OPAD mask into R2
    BL xor_key     @ Function call (i.e. R0-R3 may be modified)    
    @ All registers (R0 - R5) free to be used as needed.

    @ Call SHA-1
    @ This time destination is address from caller.
    @ R0 - First byte of data
    MOV R0, SP
    ADD R0, R0, #RAW_KEY_OFFSET
    @ R1 - Number of bytes of data
    MOV R1, #0x54 @ 84 bytes, i.e. 16 word opadded key + 5 word int hash.
    @ R2 - Destination
    LDR R2, [SP]  @ 3 Words had been pushed by this point
    ADD R2, R2, #0xC @ Offset 12 bytes
    LDR R2, [R2] @ The address in R2 points to the address that holds the address of the result.
    BL sha1_digest
    @ All registers (R0 - R5) free to be used as needed.

    @ TODO Clear memory content of stack space allocated.
    LDR R4, [SP, #0x0]
    MOV SP, R4      @ This sets SP to the value immediately prior to push.
    POP {R4-R5, PC}

@ Constants for IPAD and OPAD
.align 4 
ipad:
    .word 0x36363636
opad:
    .word 0x5C5C5C5C    

@ R4 is not 0 so calculate padding needed.
@ Store the result in R4, can also use R5
calc_padding:
    MOV R5, #0x4
    SUB R4, R5, R4
    B create_stack

@ The key is too big so hash it.
@ R0 - First byte of key
@ R1 - Length of key
@ R2 - Destination of hash
hash_the_key:
    MOV R4, R2     @ Cache R2 in R4 as it may be modified.
    BL sha1_digest
    @ This will have written 20 bytes (5 words)
    MOV R2, R4

    MOV R1, #0x5   @ 5 words to reverse
reverse_word2:
    LDR R0, [R2]
    REV R0, R0
    STR R0, [R2]
    ADD R2, R2, #0x4
    SUB R1, R1, #0x1
    BNE reverse_word2


    @MOV R5, #0x14   @ 20 bytes
    @ADD R2, R2, R5  @ Move address on by 20 bytes
    MOV R3, #0x2C   @ 44 bytes i.e. 64 - 20
    @ Adjust registers and branch to pad_key_byte to
    @ continue padding.
    B key_padding

@ Start Function:
@   xor_key:
@
@  XOR a 16 word key
@
@  TODO - Could this be a macro?
@
@ R0 - Source Address
@ R1 - Dest Address
@ R2 - Mask Value
.thumb_func
xor_key:
    PUSH {R4-R5, LR}
    @ Although manipulating words count in bytes as addresses will need
    @ adjusting 4 bytes at a time.
    @ R3 - Bytes Left
    @ R4 - Current Word
    @ R5 - Constant 0x4 
    MOV R3, #0x40       @ 64 Bytes
    MOV R5, #0x4
xor_word:
    LDR R4, [R0]
    EOR R4, R4, R2
    STR R4, [R1]
    SUB R3, R3, R5
    BEQ xor_return    @ That was last word, return.
    @ Increment both addresses to next word.
    ADD R0, R0, R5
    ADD R1, R1, R5
    B xor_word      @ Mask the next word.
xor_return:
    POP {R4-R5, PC}    @ Return to caller.
@ End Function:
@   xor_key:


