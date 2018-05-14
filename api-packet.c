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
#include "api.h"
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>

int get_api_packet(int fd, struct sshout_api_packet **packet, uint32_t *length) {
	uint32_t orig_length;
	int s;
	do {
		s = read(fd, &orig_length, sizeof orig_length);
	} while(s < 0 && errno == EINTR);
	if(s < 0) return GET_PACKET_ERROR;
	if(!s) return GET_PACKET_EOF;
	if(s < sizeof orig_length) return GET_PACKET_SHORT_READ;
	*length = ntohl(orig_length);
	if(*length > SSHOUT_API_PACKET_MAX_LENGTH) {
		return GET_PACKET_TOO_LARGE;
	}
	*packet = malloc(sizeof orig_length + *length);
	if(!*packet) return GET_PACKET_OUT_OF_MEMORY;
	(*packet)->length = orig_length;
	do {
		s = read(fd, (char *)*packet + sizeof orig_length, *length);
	} while(s < 0 && errno == EINTR);
	if(s < 0) return GET_PACKET_ERROR;
	if(!s) return GET_PACKET_EOF;
	if(s < *length) return GET_PACKET_SHORT_READ;
	return 0;
}
