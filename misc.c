/*
 * Copyright 2015-2018 Rivoreo
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#include "common.h"

int is_valid_user_name(const char *name) {
	unsigned int len = 0;
	if(!*name) return 0;
	do {
		switch(*name) {
			case 0x4:
			case '\b':
			case '	':
			case '\n':
			case '':
			case '':
			case '\r':
			case '"':
			case '#':
			case '\'':
			case '*':
			case '/':
			case '\\':
			case 0x7f:
				return 0;
		}
		if(++len > USER_NAME_MAX_LENGTH) return 0;
	} while(*++name);
	return 1;
}
