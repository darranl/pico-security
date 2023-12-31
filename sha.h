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

/*****************/
/* SHA Functions */
/*****************/

#include <stdio.h>
#include "pico/stdlib.h"
#include "sha-debug.h"

extern void sha1_digest(char *data, uint32_t data_length, uint32_t *digest);

