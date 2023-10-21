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

extern void hmac_sha1(char *key, uint32_t key_length, char *text, uint32_t text_length, uint32_t *mac);
