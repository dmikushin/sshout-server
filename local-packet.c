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
#include <stdlib.h>
#include <errno.h>

int get_local_packet(int fd, struct local_packet **packet) {
	size_t length;
	int s;
	do {
		s = read(fd, &length, sizeof length);
	} while(s < 0 && errno == EINTR);
	if(s < 0) return GET_PACKET_ERROR;
	if(!s) return GET_PACKET_EOF;
	if(s < sizeof length) return GET_PACKET_SHORT_READ;
	if(length > LOCAL_PACKET_MAX_LENGTH) {
		*(unsigned int *)packet = length;
		return GET_PACKET_TOO_LARGE;
	}
	*packet = malloc(sizeof length + length);
	if(!*packet) {
		*(unsigned int *)packet = length;
		return GET_PACKET_OUT_OF_MEMORY;
	}
	(*packet)->length = length;
	do {
		s = read(fd, (char *)*packet + sizeof length, length);
	} while(s < 0 && errno == EINTR);
	if(s < 0) return GET_PACKET_ERROR;
	if(!s) return GET_PACKET_EOF;
	if(s < length) return GET_PACKET_SHORT_READ;
	return 0;
}
