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

// Based on public domain code from Wikibooks

#include <stddef.h>
#include <stdint.h>

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static const unsigned char d[] = {
	66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
	54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
	29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66
};

int base64_decode(const char *in_buffer, size_t in_len, void *out_buffer, size_t buffer_size) { 
	const char *end = in_buffer + in_len;
	unsigned char *out_p = out_buffer;
	char iter = 0;
	uint32_t buf = 0;
	size_t len = 0;

	while(in_buffer < end) {
		unsigned char c = d[*in_buffer++];

		switch(c) {
			case WHITESPACE: continue;   /* skip whitespace */
			case INVALID:    return -1;  /* invalid input, return error */
			case EQUALS:                 /* pad character, end of data */
					 in_buffer = end;
					 continue;
			default:
					 buf = buf << 6 | c;
					 iter++; // increment the number of iteration
					 /* If the buffer is full, split it into bytes */
					 if(iter == 4) {
						 if((len += 3) > buffer_size) return len; /* buffer overflow */
						 *(out_p++) = (buf >> 16) & 255;
						 *(out_p++) = (buf >> 8) & 255;
						 *(out_p++) = buf & 255;
						 buf = 0; iter = 0;
					 }   
		}
	}

	if(iter == 3) {
		if((len += 2) > buffer_size) return len; /* buffer overflow */
		*(out_p++) = (buf >> 10) & 255;
		*(out_p++) = (buf >> 2) & 255;
	} else if(iter == 2) {
		if(++len > buffer_size) return len; /* buffer overflow */
		*(out_p++) = (buf >> 4) & 255;
	}

	return len;
}
