/* Copyright 2023, Darran A Lofthouse
 *
 * This file is part of pico-security.
 *
 * pico-security is free software: you can redistribute it and/or modify it under the terms 
 * of the GNU General Public License as published by the Free Software Foundation, either 
 * version 3 of the License, or (at your option) any later version.
 *
 * pico-security is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with pico-security.
 * If  not, see <https://www.gnu.org/licenses/>. 
 */

#include <stdio.h>
#include "pico/stdlib.h"

/*
 * calculate_hotp
 *   For a given shared sectrt and count value generate the appropriate 6 digit HOTP value.
 * 
 * Arguments:
 *     shared_secret - Pointer to char array containing the shared secret.
 *     secret_length - Length of the shared secret.
 *     counter       - Current count value (8 bytes).
 *     result        - Pointer to 6 element short array to return the result.
 */
extern void calculate_hotp(char *shared_secret, uint32_t secret_length, uint64_t counter, short *result);
