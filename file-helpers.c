/* Secure Shout Host Oriented Unified Talk
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

int fgetline(FILE *f, char *line, size_t len) {
	size_t i = 0;
	int c;
	while((c = fgetc(f)) != '\n') {
		if(c == EOF) {
			if(!i) return -1;
			break;
		}
		if(i >= len - 1) return -2;
		line[i++] = c;
	}
	line[i] = 0;
	return i;
}

int fbackwardoverwrite(FILE *f, size_t len) {
	long int offset = ftell(f);
	if(offset < 0) return -1;
	if(len > offset) {
#if 0
		errno = ERANGE;
		return -1;
#else
		len = offset;
#endif
	}
	long int overwrite_start = offset - len;
	char buffer[1024];
	size_t item_count, ss = 0;
	long int current_offset;
	do {
		item_count = fread(buffer, sizeof buffer, 1, f);
		if(!item_count && ferror(f)) return -1;
		current_offset = ftell(f);
		long int s = current_offset - offset - ss;
		fseek(f, overwrite_start + ss , SEEK_SET);
		if(!s) break;
		if(!fwrite(buffer, s, 1, f)) return -1;
		ss += s;
	} while(item_count && fseek(f, current_offset, SEEK_SET) != -1);
	if(ferror(f)) return -1;
	clearerr(f);
	fflush(f);
	assert(ftell(f) == overwrite_start + ss);
	if(ftruncate(fileno(f), ftell(f)) < 0) return -1;
	return fseek(f, overwrite_start, SEEK_SET);
}
