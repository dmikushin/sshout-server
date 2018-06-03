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

#ifndef _SSHOUT_API_H
#define _SSHOUT_API_H

#define SSHOUT_API_HELLO 1
#define SSHOUT_API_GET_ONLINE_USER 2
#define SSHOUT_API_SEND_MESSAGE 3
#define SSHOUT_API_GET_MOTD 4

#define SSHOUT_API_PASS 128
#define SSHOUT_API_ONLINE_USERS_INFO 129
#define SSHOUT_API_RECEIVE_MESSAGE 130
#define SSHOUT_API_USER_STATE_CHANGE 131
#define SSHOUT_API_ERROR 132
#define SSHOUT_API_MOTD 133

#define SSHOUT_API_MESSAGE_TYPE_PLAIN 1
#define SSHOUT_API_MESSAGE_TYPE_RICH 2
#define SSHOUT_API_MESSAGE_TYPE_IMAGE 3

#define SSHOUT_API_ERROR_SERVER_CLOSED 1
#define SSHOUT_API_ERROR_LOCAL_PACKET_CORRUPT 2
#define SSHOUT_API_ERROR_LOCAL_PACKET_TOO_LARGE 3
#define SSHOUT_API_ERROR_OUT_OF_MEMORY 4
#define SSHOUT_API_ERROR_INTERNAL_ERROR 5
#define SSHOUT_API_ERROR_USER_NOT_FOUND 6
#define SSHOUT_API_ERROR_MOTD_NOT_AVAILABLE 7

#define SSHOUT_API_PACKET_MAX_LENGTH (1024 * 1024)

#include <stdint.h>

struct sshout_api_packet {
	uint32_t length;
	uint8_t type;
	uint8_t data[0];
};

#endif
