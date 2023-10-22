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
@ 0x08  5 Words - Calculated HMAC
@ 0x00  2 Words - 8 byte Count (Adjusted to big endien, i.e. natural byte order)

.equ STACK_SPACE, 0x1C  @ 7 words / 28 bytes

.equ OTP_ADDRESS_OFFSET, 0x00  @ TODO Calculate once we know how much was pushed.
.equ HMAC_OFFSET, 0x08
.equ BYTE_COUNT_LSB_OFFSET, 0x04
.equ BYTE_COUNT_MSB_OFFSET, 0x00

@ Start Function:
@  extern void calculate_hotp(char *shared_secret, uint32_t secret_length, uint64_t counter, short *result);
@
@ Initial Registers:
@   R0 = Address of secret.
@   R1 = Length of secret.
@   R2 = Count least significant bytes.
@   R3 = Count most significant bytes.
@
@ On the stack:
@   Pointer to the address to hold the resulting 6 digit OTP.
@
@ Intermediate Registers
@   SP will be pointing to the address that holds the address of the otp array.
@
@ Return Value - None (Could use return later to indicate an error state)
.thumb_func                @ We may B to SDK code
.global calculate_hotp     @ This line says the label needs to be global.
 calculate_hotp:           @ This then defines the label.
    PUSH {LR}
    SUB SP, #STACK_SPACE
    @ Step 1 - Move count into memory in correct byte order
    REV R3, R3    @ Reverse and store most significant part of count. 
    STR R3, [SP]
    REV R2, R2    @ Reverse and store least significant part of count.
    STR R2, [SP, #BYTE_COUNT_LSB_OFFSET]
    @ Step 2 - Calculate HMAC
    MOV R2, SP    @ Set R2 to address of adjusted count
    @ Going to borrow R3 to calculate address of result.
    ADD R3, SP, #HMAC_OFFSET
    SUB SP, #0x4  @ Need one more word on stack for HMAC call.
    STR R3, [SP]  @ Store the address of the HMAC result.
    MOV R3, #0x8  @ Now set the data length to 8, i.e. 8 byte count.
    BL hmac_sha1
    ADD SP, #0x4  @ Restore SP after HMAC call.
    @ R0 to R3 are now all free for further use.

    @ Log the stack space.
    MOV R0, SP
    MOV R1, #STACK_SPACE
    ADD R1, #0x8
    BL log_data  @ All data is copied, key is copied or hashed and padded.

    @ Reverse bytes in calculated HMAC as next step operates on bytes in order.
    MOV R2, SP
    ADD R2, R2, #HMAC_OFFSET
    MOV R1, #0x5   @ 5 words to reverse
reverse_word:
    LDR R0, [R2]
    REV R0, R0
    STR R0, [R2]
    ADD R2, R2, #0x4
    SUB R1, R1, #0x1
    BNE reverse_word

    @ Log the stack space.
    MOV R0, SP
    MOV R1, #STACK_SPACE
    ADD R1, #0x8
    BL log_data  @ All data is copied, key is copied or hashed and padded.
    
    ADD SP, #STACK_SPACE
    POP {PC}