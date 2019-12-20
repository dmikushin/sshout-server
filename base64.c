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

#include "base64.h"
#include <stddef.h>
#include <stdint.h>

int base64_encode(const void *data_buf, size_t data_len, char *result, size_t out_buffer_size, int flags) {
	static const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *data = (const uint8_t *)data_buf;
	size_t out_i = 0;
	size_t x;
	uint32_t n = 0;
	uint8_t n0, n1, n2, n3;

	/* Increment over the length of the string, three characters at a time */
	for (x = 0; x < data_len; x += 3) {
		/* These three 8-bit (ASCII) characters become one 24-bit number */

		/* parenthesis needed; compiler depending on flags can do the
		 shifting before conversion to uint32_t, resulting to 0 */
		n = ((uint32_t)data[x]) << 16;

		if((x+1) < data_len) {
			/* parenthesis needed; compiler depending on flags
			 can do the shifting before conversion to uint32_t,
			 resulting to 0 */
			n += ((uint32_t)data[x+1]) << 8;
		}

		if((x+2) < data_len) n += data[x+2];

		/* this 24-bit number gets separated into four 6-bit numbers */
		n0 = (uint8_t)(n >> 18) & 63;
		n1 = (uint8_t)(n >> 12) & 63;
		n2 = (uint8_t)(n >> 6) & 63;
		n3 = (uint8_t)n & 63;

		/*
		 * if we have one byte available, then its encoding is spread
		 * out over two characters
		 */
		if(out_i >= out_buffer_size) return -1;   /* indicate failure: buffer too small */
		result[out_i++] = base64chars[n0];
		if(out_i >= out_buffer_size) return -1;   /* indicate failure: buffer too small */
		result[out_i++] = base64chars[n1];

		/*
		 * if we have only two bytes available, then their encoding is
		 * spread out over three chars
		 */
		if((x+1) < data_len) {
			if(out_i >= out_buffer_size) return -1;   /* indicate failure: buffer too small */
			result[out_i++] = base64chars[n2];
		}

		/*
		 * if we have all three bytes available, then their encoding is spread
		 * out over four characters
		 */
		if((x+2) < data_len) {
			if(out_i >= out_buffer_size) return -1;   /* indicate failure: buffer too small */
			result[out_i++] = base64chars[n3];
		}
	}

	if(flags & BASE64_ADD_PADDING) {
		/*
		 * Create and add padding that is required if we did not have a multiple of 3
		 * number of characters available
		 */
		int pad_count = data_len % 3;
		while(pad_count % 3) {
			if(out_i >= out_buffer_size) return -1;
			result[out_i++] = '=';
			pad_count++;
		}
	}

	if(out_i >= out_buffer_size) return -1;   /* indicate failure: buffer too small */
	result[out_i] = 0;

	return 0;   /* indicate success */
}

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
		unsigned char c = d[(unsigned char)*in_buffer++];

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
						if(len + 1 > buffer_size) return len;
						*(out_p++) = (buf >> 16) & 255;
						if(++len + 1 > buffer_size) return len;
						*(out_p++) = (buf >> 8) & 255;
						if(++len + 1 > buffer_size) return len;
						*(out_p++) = buf & 255;
						len++;
						buf = 0; iter = 0;
					 }   
		}
	}

	if(iter == 3) {
		if(len + 1 > buffer_size) return len;
		*(out_p++) = (buf >> 10) & 255;
		if(++len + 1 > buffer_size) return len;
		*(out_p++) = (buf >> 2) & 255;
		len++;
	} else if(iter == 2) {
		if(len + 1 > buffer_size) return len;
		*(out_p++) = (buf >> 4) & 255;
		len++;
	}

	return len;
}
