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

#ifndef _SYNCRW_H
#define _SYNCRW_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int sync_read(int, void *, size_t);
int sync_write(int, const void *, size_t);

#ifdef __cplusplus
}
#endif

#endif
