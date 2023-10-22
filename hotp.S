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
@  extern void calculate_hotp(char *shared_secret, uint32_t secret_length, uint64_t counter, short *result);
@
@ Initial Registers:
@
@ Intermediate Registers
@
@ Return Value - None (Could use return later to indicate an error state)
.thumb_func                @ We may B to SDK code
.global calculate_hotp     @ This line says the label needs to be global.
 calculate_hotp:           @ This then defines the label.
     PUSH {LR}

     POP {PC}