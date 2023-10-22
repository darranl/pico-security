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

#include "hardware/regs/addressmap.h"
#include "hardware/regs/sio.h"

.macro divider_delay
      // delay 8 cycles
      b   1f
1:    b   1f
1:    b   1f
1:    b   1f
1:
.endm

@ Stack Space
@ 
@ 0x08  5 Words - Calculated HMAC
@ 0x00  2 Words - 8 byte Count (Adjusted to big endien, i.e. natural byte order)

.equ STACK_SPACE, 0x1C  @ 7 words / 28 bytes

.equ OTP_ADDRESS_OFFSET, 0x20  @ Assuming we only pushed one register.
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
    
    @ Calculate truncated HMAC
    ADD R0, SP, #HMAC_OFFSET        
    LDRB R1, [R0, #0x13]    @ Load Byte 19 
    MOV R2, #0x4
    AND R1, R1, R2         @ Mask R1 so it contains last 4 bits
    ADD R0, R0, R1         @ Now R0 points to the first byte we will include in the truncated HMAC

    MOV R1, #0x4           @ 4 bytes to process
load_byte:
    LDRB R2, [R0]
    LSL R3, #0x8
    ORR R3, R2, R3
    ADD R0, R0, #0x1
    SUB R1, R1, #0x1
    BNE load_byte
    @ Now R3 contains the truncated HMAC, need to drop most significiant bit
    LDR R2, msb_mask
    AND R3, R3, R2
    @ Calculate HMAC mod 1,000,000 - only R3 in use.
    @ Going to skip the mod step as it appears the best
    @ approach to convert to decimal digits is divide by 10. 6 times.

    @ Set the divisor to 10 once as will be the same for all digits.
    MOV R0, #0xA
    LDR R2, =SIO_BASE
    STR R0, [R2, #SIO_DIV_UDIVISOR_OFFSET]

    @ Convert result into separate digits in result array
    @ R0 - Base address of result array.
    LDR R0, [SP, #OTP_ADDRESS_OFFSET]
    @ R1 - Digits to convert
    MOV R1, #0x5              @ Hard code 5 for now (0 to 5)
extract_digit:
    STR R3, [R2, #SIO_DIV_UDIVIDEND_OFFSET]
    divider_delay
    LDR R3, [R2, #SIO_DIV_REMAINDER_OFFSET]
    STRB R3, [R0, R1]
    LDR R3, [R2, #SIO_DIV_QUOTIENT_OFFSET]  @ Also clears any CSR dirty flag.
    SUB R1, R1, #0x1
    BPL extract_digit     @ If zero or above keep going.
    
    ADD SP, #STACK_SPACE
    POP {PC}

.align 4
msb_mask:
    .word 0x7FFFFFFF

    