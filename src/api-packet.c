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

#include "sshout/api.h"
#include "common.h"
#include "syncrw.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int get_api_packet(int fd, struct sshout_api_packet **packet, uint32_t *length,
                   int block_read) {
  uint32_t orig_length;
  int s;
  if (block_read)
    s = sync_read(fd, &orig_length, sizeof orig_length);
  else
    do {
      s = read(fd, &orig_length, sizeof orig_length);
    } while (s < 0 && errno == EINTR);
  if (s < 0)
    return GET_PACKET_ERROR;
  if (!s)
    return GET_PACKET_EOF;
  if ((size_t)s < sizeof orig_length)
    return block_read ? GET_PACKET_EOF : GET_PACKET_SHORT_READ;
  *length = ntohl(orig_length);
  if (*length < 1)
    return GET_PACKET_TOO_SMALL;
  if (*length > SSHOUT_API_PACKET_MAX_LENGTH)
    return GET_PACKET_TOO_LARGE;
  *packet = malloc(sizeof orig_length + *length);
  if (!*packet)
    return GET_PACKET_OUT_OF_MEMORY;
  (*packet)->length = orig_length;
  if (block_read)
    s = sync_read(fd, (char *)*packet + sizeof orig_length, *length);
  else
    do {
      s = read(fd, (char *)*packet + sizeof orig_length, *length);
    } while (s < 0 && errno == EINTR);
  int r = 0;
  if (s < 0)
    r = GET_PACKET_ERROR;
  else if (!s)
    r = GET_PACKET_EOF;
  else if ((size_t)s < *length)
    r = block_read ? GET_PACKET_EOF : GET_PACKET_SHORT_READ;
  if (r)
    free(*packet);
  return r;
}
