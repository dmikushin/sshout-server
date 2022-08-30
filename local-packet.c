/* Part of SSHOUT
 * Copyright 2015-2022 Rivoreo
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

int get_local_packet(int fd, struct local_packet **packet, struct private_buffer *buffer) {
	struct local_packet **p = buffer ? (struct local_packet **)&buffer->buffer : packet;
	size_t skip = 0;
	size_t length;
	int s;
	if(buffer && buffer->buffer) {
		length = buffer->total_length;
		skip = buffer->read_length;
	} else {
		do {
			s = read(fd, &length, sizeof length);
		} while(s < 0 && errno == EINTR);
		if(s < 0) return GET_PACKET_ERROR;
		if(!s) return GET_PACKET_EOF;
		if((size_t)s < sizeof length) return GET_PACKET_SHORT_READ;
		if(length > LOCAL_PACKET_MAX_LENGTH) {
			*(unsigned int *)packet = length;
			return GET_PACKET_TOO_LARGE;
		}
		*p = malloc(sizeof length + length);
		if(!*p) {
			*(unsigned int *)packet = length;
			return GET_PACKET_OUT_OF_MEMORY;
		}
		//((struct local_packet *)*p)->length = length;
		(*p)->length = length;
		if(buffer) {
			buffer->total_length = length;
			buffer->read_length = 0;
		}
	}
	do {
		s = read(fd, (char *)*p + sizeof length + skip, length - skip);
	} while(s < 0 && errno == EINTR);
	int r = 0;
	if(s < 0) r = GET_PACKET_ERROR;
	else if(!s) r = GET_PACKET_EOF;
	else if(skip + s < length) {
		if(buffer) {
			buffer->read_length += s;
			return GET_PACKET_INCOMPLETE;
		}
		r = GET_PACKET_SHORT_READ;
	}
	if(r) free(*p);
	if(buffer) {
		*packet = (struct local_packet *)buffer->buffer;
		buffer->buffer = NULL;
		buffer->total_length = 0;
		buffer->read_length = 0;
	}
	return r;
}
