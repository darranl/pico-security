
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

@#define LOG_ARRAY

@ SHA Stack Space
@   1 word  =   4 Bytes [Var TEMP]
@   1 word  =   4 Bytes [Var E]
@   1 word  =   4 Bytes [Var D]
@   1 word  =   4 Bytes [Var V]
@   1 word  =   4 Bytes [Var B]
@   1 word  =   4 Bytes [Var A]
@   1 word  =   4 Bytes [Status] - Likely only needs a byte if anything else needs some of this word.
@   1 Word  =   4 Bytes [Address of next byte]
@   1 Word  =   4 Bytes [Bytes remaining]
@   1 Word  =   4 Byes [Bit Count]
@   1 Word  =   4 Bytes [Address of result]
@  80 Words = 320 Bytes [W array]
@    TOTAL = 364 / 0x16C
@
@ SP + 360 / 0x168 = Var TEMP
@ SP + 356 / 0x164 = Var E
@ SP + 352 / 0x160 = Var D
@ SP + 348 / 0x15C = Var C
@ SP + 344 / 0x158 = Var B
@ SP + 340 / 0x154 = Var A
@ SP + 336 / 0x150 = Status
@ SP + 332 / 0x14C = Address of next byte
@ SP + 328 / 0x148 = Bytes Remaining
@ SP + 324 / 0x144 = Bit Count Address
@ SP + 320 / 0x140 = Result Address 
@ SP + 316 = W[79]
@ ...
@ SP + 4 = W[1]
@ SP + 0 = W[0]

@ Var A through Var TEMP could be allocated later, however unless we start calling
@ lots of other functions it is inevitable that we will need the variables so alllocate
@ in one go.

.equ STACK_SPACE, 0x16C
@ Memory offsets (from SP)
.equ VAR_TEMP, 0x168
.equ VAR_E, 0x164
.equ VAR_D, 0x160
.equ VAR_C, 0x15C
.equ VAR_B, 0x158
.equ VAR_A, 0x154
.equ STATUS, 0x150
.equ NEXT_BYTE, 0x14C
.equ BYTES_REMAINING, 0x148
.equ BIT_COUNT, 0x144
.equ RESULT_ADDRESS, 0x140

.equ BEGINNING,             0x0
.equ MASK_PAD_STARTED,      0x1
.equ MASK_LENGTH_STARTED,   0x2
.equ MASK_LENGTH_COMPLETED, 0x3

.equ A_E_SPACE, 0x14   @ Stack space needed to hold A to E

@ Start Function:
@  extern void sha1_digest(char *data, uint32_t data_length, uint32_t *digest);
@
@ Initial Registers
@   R0 - Pointer to first char/byte of data.
@   R1 - Number of bytes remaining.
@   R2 - Pointer to address to hold 160 bit (20 bytes or 5 words) hash.
@ Intermediate Registers
@ 
@ Return Value - None (May use return to indicate error state)
.thumb_func             @ We may B to SDK code
.global sha1_digest     @ This line says the label needs to be global.
 sha1_digest:           @ This then defines the label.
    PUSH {R4-R7, LR}    @ Push all registers 4-11 so we can use them all.
    MOV R4, R8          @ TODO Check did we need them all?
    MOV R5, R9
    MOV R6, R10
    MOV R7, R11
    PUSH {R4-R7}
@ Step 1 - Use memory reserved for response to hold initial values for H0-H4 
@ R3 - Counter
@ R4 - Base address of constants.
    MOV R3, #0                  @ Start a loop counter at 0
    LDR R4, =h_initial          @ Set R4 to the base address of the defined constants.
start_load:    LDR R5, [R4, R3] @ Load the constant using the R3 offset (TODO Could DMA be better?)
    STR R5, [R2, R3]            @ Store the constant in the response using the R3 offset
    ADD R3, #4                  @ Increment by 4 i.e. one word
    CMP R3, #16                 @ Same as SUBS so R3 - 16 
                                @ N (Set when negative) Z (Set when operation was 0) C (Set when resulted in carry) V (Set when overflow)
                                @ Carry = result of substraction was positive or 0.
    BLS start_load              @ Lower or same C=0 or Z=1

@ Step 1.5 Initialise initial state / memory.
    SUB SP, #STACK_SPACE       @ Allocate stack space as defined above.

    STR R0, [SP, #NEXT_BYTE]       @ Save the address of the next byte to ram
    STR R1, [SP, #BYTES_REMAINING] @ Save the count of remaining bytes
    STR R2, [SP, #RESULT_ADDRESS] @ Store the address of the result on the allocated stack space.
    @ Caclulate total bits, we don't need to add as we go.
    MOV R3, #8                 @ 8 bits per byte
    MUL R3, R1, R3            @ Total bytes multiples by bits per byte
    STR R3, [SP, #BIT_COUNT]   @ Store total bits until time it is needed.
@ R2 - Status Register
    MOV R2, #0
    STR R2, [SP, #STATUS]     @ Store the status value

@ By this point we have preserved the incomming parameters onto the heap, the start of the
@ population loop will retrieve them from RAM so can begin with a completely new set of
@ registers.
@
@ This does add a bit of an overhead with a redundant save then load, but it cleans up the
@ register use so we don't need to be protecting the lowest registers if we make function calls.


@ Step 2 - Create and populate the 80 word array
@ R4 - Counter / Index (1 = 1 word) W[0]...W[79]
@ R5 - Next Byte
@ R6 - Bytes Remaining
@ R7 - Status

populate_from_data:
    MOV R4, #0                      @ Starting word count 0-15
    LDR R5, [SP, #NEXT_BYTE]        @ Restore address of next byte.
    LDR R6, [SP, #BYTES_REMAINING]  @ Restore current count of bytes remaining.
    LDR R7, [SP, #STATUS]           @ Restore the status value.
next_word_from_data:              @ Come back here to begin a word.
    @ R0 - Word being  assembled to save
    @ If !MASK_PAD_STARTED populate a word from data.
    CMP R7, #BEGINNING
    BEQ start_word_from_data   @ Uses R1, R2 as temp registers.
    MOV R0, #0                 @ If padding started the majority of words now get set to 0
    CMP R4, #14                @ First word to hold length
    BEQ start_length           @ We know most significant portion is going to be 0 as we don't have enough RAM
    CMP R4, #15
    BEQ end_length             @ Populates R0 with length if appropriate.
save_word:
    MOV R2, R4
    MOV R1, SP 
    BL save_word_to_ram        @ Branch to save the word to RAM
    ADD R4, #1
    CMP R4, #15                 @ Same as SUBS so R3 - 15 
                                @ N (Set when negative) Z (Set when operation was 0) C (Set when resulted in carry) V (Set when overflow)
                                @ Carry = result of substraction was positive or 0.
    BLS next_word_from_data     @ Lower or same C=0 or Z=1  - BLS != BL
    @ Reached the end of populating 0...15 so save registers back to stack to we can resuse.
    STR R5, [SP, #NEXT_BYTE]       @ Save the address of the next byte to ram
    STR R6, [SP, #BYTES_REMAINING] @ Save the count of remaining bytes
    STR R7, [SP, #STATUS]          @ Save the possibly updated status

@ Apart from R4 which we are continuing, all other registeres are free.
@   Will be calling functions so best avoid R0-R3
@ We continue with R4, this time going to W[79]
@ R5 Hold word being calculated until it is moved to R0 to store.
calculate_remaining_words:
    @ W[R4 - 3]
    SUB R0, R4, #3
    MOV R1, SP 
    BL load_word_from_ram
    MOV R5, R0
    @ W[R3 - 8]
    MOV R0, R4
    SUB R0, R0, #8
    MOV R1, SP                @ If treating as a function we can't assume not modiffied.
    BL load_word_from_ram
    EOR R5, R5, R0
    @ W[R3 - 14]
    MOV R0, R4
    SUB R0, R0, #14
    MOV R1, SP
    BL load_word_from_ram
    EOR R5, R5, R0
    @ W[R3 - 16]
    MOV R0, R4
    SUB R0, R0, #16
    MOV R1, SP
    BL load_word_from_ram
    EOR R5, R5, R0
    @ Circular Left Shift by 1 (ROR by 32-1)
    MOV R0, #31       @ Borrow R0 will be set to R4 shortly.
    ROR R5, R5, R0
    @ Now save calculated word back to RAM
    MOV R0, R5
    MOV R1, SP    
    MOV R2, R4
    BL save_word_to_ram
    ADD R4, #1
    CMP R4, #79
    BLS calculate_remaining_words @ Repeat for next W[R4]

    @Temporary code to output current 80 word array.
    #ifdef LOG_ARRAY
    MOV R0, SP
    BL log_words
    #endif

    @ All registers available again.
    @ Would try and avoid an unnescesary branch but TBH the 
    @ update is quite intensive with lots of it's own branches.
    B update_h0_to_h4  @ Assumes we don't need any registers preserving.

do_we_need_another_pass:
    LDR R2, [SP, #STATUS]           @ Load status from RAM as we will not be holding up a register.
    CMP R2, #MASK_LENGTH_COMPLETED
    BNE populate_from_data      @ We haven't written the length so need another 512 bit chunk to process.

return_cleanup:
    @ Normal Clean Up to restore registers and drop stack mem.
    ADD SP, #STACK_SPACE
    POP {R4-R7}
    MOV R8, R4          @ TODO Check did we need them all? // Starting to look that way.
    MOV R9, R5
    MOV R10, R6
    MOV R11, R7    
    POP {R4-R7, PC}        @ Return (Directly sets address of program counter)

@ Function Snippets:
@  extern void sha1_digest(char *data, uint32_t data_length, uint32_t *digest);

start_word_from_data:
    @ For each word process 4 bytes 1 at a time.
    @ If we have a byte use it.
    @ If no byte and haven't already write start of padding i.e. 0x80 #128 10000000

    @ R0 - Word being assembled
    @ R1 - Count of bytes processed - Start at 4 and decrement so direct CMP not needed.
    @ R2 - Scratch register, hold value from memory etc. 
    @ R6 - Pre-populated bytes remaining
    @ R7 - Status
    MOV R1, #4                   @ Start counter of 4 bytes.
next_byte:
    SUB R6, #1                 @ Always subtract 1, once negative will remain negative.
    BPL copy_byte              @ If we have a byte jump to copy it.
    CMP R7, #0
    BEQ start_padding
    @ else fill with zeroes
    MOV R2, #0x0               @ Need to clear register to store as could be filled with old data.
store_byte:
    LSL R0, #8
    ORR R0, R2
    SUB R1, #1
    BNE next_byte               @ Not at zero yet, next byte. If we didn't branch we have finished with R4.
    B save_word

@ Copy a single byte into R6, remaining bits will be zeroed
@ Also move the start address to the next byte
@ Return to the logic that will store the byte in the word.
@
@ R2 - Scratch register, hold value from memory etc. 
@ R5 - Next Byte
copy_byte:
    LDRB R2, [R5, #0]
    ADD R5, #1             @ Move address on by one so always points to next byte.
    B store_byte

@ R7 - Status Register
@ R2 - Current single byte 
start_padding:
    MOV R7, #MASK_PAD_STARTED
    MOV R2, #0x80
    B store_byte

@ R7 - Status Register
start_length:
    MOV R7, #MASK_LENGTH_STARTED
    B save_word

@ R7 - Status Register
end_length:
    CMP R7, #MASK_LENGTH_STARTED
    BNE save_word         @ We know R5 is already 0, length wasn't started so we can't end it.
    MOV R7, #MASK_LENGTH_COMPLETED
    LDR R0, [SP, #BIT_COUNT] @ Load the previously calulated bit count.
    B save_word
@ End Function:
@  extern void sha1_digest(char *data, uint32_t data_length, uint32_t *digest);


@@@@@@@@@@@@@@@@@@@@@@
@ Separate Functions @
@@@@@@@@@@@@@@@@@@@@@@

@ Start Function:
@   update_h0_to_h4:
@
@ Split into a separate function as sha1_digest was getting too long
@ for conditional branching to code which followed.
@
@ When sha1_digest calls this function we know all registers are safe to
@ use so don't push anything to the stack, this means all addressing remains
@ relative to SP
@
.thumb_func
update_h0_to_h4:
    BL initialise_a_e   
    @ Do the 0 to 79 loop
    MOV R4, #0
    BL initialise_quarters @ Not treating as a function
next_word_a_e:
    @ R5 = TEMP=
    @ S^5(A)
    LDR R5, [SP, #VAR_A]
    @ Circular Left Shift by 5 (ROR by 32-5)
    MOV R0, #27       @ Borrow R0 as unnused.
    ROR R5, R5, R0
    ADD R5, R5, R7    @ Add K before calling thee function as
                      @ the function may move K on.
    MOV R0, R4 
    BLX R8                @ Also overwrites LR
    @BL function_one
    ADD R5, R5, R0
    LDR R0, [SP, #VAR_E]
    ADD R5, R5, R0
    MOV R0, R4
    MOV R1, SP
    BL load_word_from_ram  @ Overwrites LR so we need to save or push it.
    ADD R5, R5, R0
    @ E = D
    LDR R0, [SP, #VAR_D]
    STR R0, [SP, #VAR_E]
    @ D = C
    LDR R0, [SP, #VAR_C]
    STR R0, [SP, #VAR_D]
    @ C = S^30(B)
    LDR R0, [SP, #VAR_B]
    @ Circular Left Shift by 30 (ROR by 32-30)
    MOV R1, #2
    ROR R0, R0, R1 
    STR R0, [SP, #VAR_C]
    @ B = A
    LDR R0, [SP, #VAR_A]
    STR R0, [SP, #VAR_B]
    @ A = Temp
    STR R5, [SP, #VAR_A]

    # Next Index
    ADD R4, #1
    CMP R4, #79
    BLS next_word_a_e @ Repeat for next W[R4]

    @ No registers in use
    @ Combine A to E with H0 to H4
    @ H0 = H0 + A
    MOV R0, #0  @ Relatve Count
    LDR R1, [SP, #RESULT_ADDRESS]  @ R1 = Base address of H0-H4
    MOV R2, SP 
    LDR R3, a_relative
    ADD R2, R2, R3                  @ R2 = Base address of A-E

next_save_h:
    LDR R3, [R1, R0]       @ R3 = H[Current]
    LDR R4, [R2, R0]       @ R4 = A to E (Current)

    ADD R3, R3, R4 
    STR R3, [R1, R0]

    ADD R0, #4    @ Inrement to next word
    CMP R0, #16 @ Same as SUBS so R0 - 16 
                @ N (Set when negative) Z (Set when operation was 0) 
                @ C (Set when resulted in carry) V (Set when overflow)
                @ Carry = result of substraction was positive or 0.
    BLS next_save_h  @ Lower or same C=0 or Z=1
    @ All updated
    B do_we_need_another_pass  @ As long as this works we don't need to save LR


@ Function Snippets:
@   update_h0_to_h4:

initialise_a_e:
@ Copy H0 through H4 to A through E respectivly
    @ TODO Later consider if this can be done in advance
    @ using DMA while the previous loop runs.
    MOV R0, #0
    LDR R1, [SP, #RESULT_ADDRESS]
    MOV R2, SP
    LDR R3, a_relative
    ADD R2, R2, R3
next_h:
    LDR R3, [R1, R0]
    STR R3, [R2, R0]
    ADD R0, #4
    CMP R0, #16 @ Same as SUBS so R0 - 12 
                @ N (Set when negative) Z (Set when operation was 0) 
                @ C (Set when resulted in carry) V (Set when overflow)
                @ Carry = result of substraction was positive or 0.
    BLS next_h  @ Lower or same C=0 or Z=1
    BX LR
.align 4 
a_relative:
    .word VAR_A

@ Updates R7 to point to K for 0-19
@ Updates R8 8to point to the function for 0-19
initialise_quarters:
    LDR R0, =function_one @ Load address of function_one
    MOV R8, R0    @ and store in R8.
    LDR R7, kay_one @ First K constant
    BX LR

.align 4 
kay_one:
    .word 0x5A827999

@ End Function:
@   update_h0_to_h4:

@ Start Function:
@   load_word_from_ram:
@
@ Load a Word W[INDEX] from RAM
@
@ TODO - Should this be a macro?
@   Either way we need consistent registers in use.
@
@ R0 - Index of word  to load.
@ R1 - Base Address
@ R2 - Register used for temporary calculations.
@
@ Return Value:
@   R0 - Loaded word.
load_word_from_ram:
    MOV R2, #0x4
    MUL R0, R0, R2   @ Calculate memory offest
    LDR R0, [R1, R0]
    BX LR            @ Return to where we were called from
@ End Function:
@   load_word_from_ram:

@ Start Function:
@   save_word_to_ram:
@
@ Save a Word W[INDEX] to RAM
@
@ TODO - Could / Should this be a macro?
@   Either way we need consistent registers in use.
@
@ R0 - Word to save
@ R1 - Base Address
@ R2 - Index to save  to
@ R3 - Register used for temporary calculations.
@
@ No return value.
save_word_to_ram:
    MOV R3, #0x4
    MUL R2, R2, R3   @ Calculate memory offest
    STR R0, [R1, R2]
    BX LR            @ Return to where we were called from
@ End Function:
@   save_word_to_ram:

@ Start Function:
@   function_one:
@
@ Reserve R0 so we can pass in the index later.
@
@ Return Value:
@   R0 - Loaded word.
.thumb_func @ tells the assembler that the next symbol will point 
            @ to Arm THUMB code
function_one:
    LDR R1, [SP, #VAR_B]
    LDR R2, [SP, #VAR_C]
    AND R1, R1, R2
    LDR R2, mask
    LDR R3, [SP, #VAR_B]
    EOR R2, R2, R3
    LDR R3, [SP, #VAR_D]
    AND R2, R2, R3
    ORR R1, R1, R2
    CMP R0, #19
    BEQ set_second_quarter
return_function_one:
    MOV R0, R1            @ Set the return value
    BX LR
@Function Snippet:
@   function_one:
set_second_quarter:
    LDR R0, =function_even
    MOV R8, R0
    LDR R7, kay_two
    B return_function_one
@End Function:
@   function_one:

.align 4
mask:
    .word 0xFFFFFFFF
kay_two:
    .word 0x6ED9EBA1

@ Start Function:
@   function_even
@
@ The same function is used for 20 to 39 as is used for 60 to 79:
@
@ Reserve R0 so we can pass in the index later.
@
@ Return Value:
@   R0 - Loaded word.
.thumb_func @ tells the assembler that the next symbol will point 
            @ to Arm THUMB code
function_even:
    LDR R1, [SP, #VAR_B]
    LDR R2, [SP, #VAR_C]
    EOR R1, R1, R2 
    LDR R2, [SP, #VAR_D]
    EOR R1, R1, R2 
    CMP R0, #39             @ This is also called for 60 to 79 but we don't need
    BEQ set_third_quarter   @ a follow on from there.
return_function_even:
    MOV R0, R1            @ Set the return value
    BX LR
@Function Snippet:
@   function_one:
set_third_quarter:
    LDR R0, =function_three
    MOV R8, R0
    LDR R7, kay_three
    B return_function_even
@End Function:
@   function_even:

.align 4
kay_three:
    .word 0x8F1BBCDC

@ Start Function:
@   function_three
@
@ Reserve R0 so we can pass in the index later.
@
@ Return Value:
@   R0 - Loaded word.
.thumb_func @ tells the assembler that the next symbol will point 
            @ to Arm THUMB code
function_three:
    LDR R1, [SP, #VAR_C]
    LDR R2, [SP, #VAR_B]
    AND R1, R1, R2        @ R2 is still B
    LDR R3, [SP, #VAR_D]
    AND R2, R2, R3 
    ORR R1, R1, R2        @ R3 is still D
    LDR R2, [SP, #VAR_C]
    AND R2, R2, R3 
    ORR R1, R1, R2     
    CMP R0, #59
    BEQ set_fourth_quarter
return_function_three:
    MOV R0, R1            @ Set the return value
    BX LR
@Function Snippet:
@   function_three:
set_fourth_quarter:
    LDR R0, =function_even
    MOV R8, R0
    LDR R7, kay_four
    B return_function_one    
@End Function:
@   function_three:

.align 4
kay_four:
    .word 0xCA62C1D6

.data
h_initial: .word 0x67452301    @ Is this the correct way to store our constants?
  .word 0xEFCDAB89 
  .word 0x98BADCFE
  .word 0x10325476
  .word 0xC3D2E1F0

