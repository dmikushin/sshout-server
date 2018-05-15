/*
 * Copyright 2015-2016 Rivoreo
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#include <unistd.h>
#include <errno.h>

int sync_read(int fd, void *buffer, size_t count) {
	char *p = buffer;
	do {
		int s = read(fd, p, count);
		if(s < 0) {
			if(errno == EINTR) continue;
			return -1;
		}
		if(!s) return p - (char *)buffer;
		count -= s;
		p += s;
	} while(count > 0);
	return p - (char *)buffer;
}

int sync_write(int fd, const void *buffer, size_t count) {
	const char *p = buffer;
	do {
		int s = write(fd, p, count);
		if(s < 0) {
			if(errno == EINTR) continue;
			return -1;
		}
		if(!s) return p - (char *)buffer;
		count -= s;
		p += s;
	} while(count > 0);
	return p - (char *)buffer;
}
