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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int client_mode(const char *user_name) {
	const char *client_address = getenv("SSH_CLIENT");
	if(!client_address) {
		fputs("client mode can only be used in a SSH session\n", stderr);
		return 1;
	}
}
