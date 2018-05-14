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
#include "client.h"
#include "api.h"
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

void send_api_error(int code, const char *message) {
}

void send_api_message(struct local_message *local_message) {
}

void send_api_online_users(struct local_online_users_info *local_info) {
}

void send_api_user_state(const char *user, int online) {
}


static void client_api_init_io(const char *user_name) {
	char ident[8 + USER_NAME_MAX_LENGTH + 4 + 1];
	snprintf(ident, sizeof ident, "sshoutd:%s:api", user_name);
	openlog(ident, LOG_PID, LOG_DAEMON);
}

static void client_api_do_local_packet(int fd) {
	struct local_packet *packet;
	switch(get_local_packet(fd, &packet)) {
		case GET_PACKET_EOF:
			send_api_error(SSHOUT_API_ERROR_SERVER_CLOSED, "Server closed connection");
			close(fd);
			exit(0);
		case GET_PACKET_ERROR:
			send_api_error(SSHOUT_API_ERROR_LOCAL_PACKET_CORRUPT, strerror(errno));
			close(fd);
			exit(1);
		case GET_PACKET_SHORT_READ:
			send_api_error(SSHOUT_API_ERROR_LOCAL_PACKET_CORRUPT, "Local packet short read");
			close(fd);
			exit(1);
		case GET_PACKET_TOO_LARGE:
			send_api_error(SSHOUT_API_ERROR_LOCAL_PACKET_TOO_LARGE, "Received local packet too large");
			close(fd);
			exit(1);
		case GET_PACKET_OUT_OF_MEMORY:
			send_api_error(SSHOUT_API_ERROR_OUT_OF_MEMORY, "Out of memory");
			close(fd);
			exit(1);
		case 0:
			break;
		default:
			send_api_error(SSHOUT_API_ERROR_INTERNAL_ERROR, "Internal error");
			abort();
	}
	switch(packet->type) {
		case SSHOUT_LOCAL_DISPATCH_MESSAGE:
			send_api_message((struct local_message *)packet->data);
			break;
		case SSHOUT_LOCAL_ONLINE_USERS_INFO:
			send_api_online_users((struct local_online_users_info *)packet->data);
			break;
		case SSHOUT_LOCAL_USER_ONLINE:
		case SSHOUT_LOCAL_USER_OFFLINE:
			send_api_user_state((char *)packet->data, packet->type == SSHOUT_LOCAL_USER_ONLINE);
			break;
		case SSHOUT_LOCAL_USER_NOT_FOUND:
			send_api_error(SSHOUT_API_ERROR_USER_NOT_FOUND, (char *)packet->data);
			break;
		default:
			syslog(LOG_WARNING, "Unknown local packet type %d", packet->type);
			break;
	}
	free(packet);
}

static void client_api_do_stdin(int fd) {
	struct sshout_api_packet *packet;
	uint32_t length;
	int e = get_api_packet(STDIN_FILENO, &packet, &length);
	switch(e) {
		case GET_PACKET_EOF:
			close(fd);
			exit(0);
		case GET_PACKET_ERROR:
			syslog(LOG_ERR, "STDIN_FILENO: %s", strerror(errno));
			close(fd);
			exit(1);
		case GET_PACKET_SHORT_READ:
			syslog(LOG_ERR, "STDIN_FILENO short read");
			close(fd);
			exit(1);
		case GET_PACKET_TOO_LARGE:
			syslog(LOG_ERR, "Received API packet too large (%u bytes)", length);
			close(fd);
			exit(1);
		case GET_PACKET_OUT_OF_MEMORY:
			syslog(LOG_ERR, "Out of memory");
			close(fd);
			exit(1);
		case 0:
			break;
		default:
			syslog(LOG_ERR, "Unknown error %d from get_api_packet", e);
			abort();
	}
	// TODO
	//switch(ntohs(packet->type))
	free(packet);
}

void client_api_get_actions(struct client_backend_actions *a) {
	a->init_io = client_api_init_io;
	a->do_local_packet = client_api_do_local_packet;
	a->do_stdin = client_api_do_stdin;
	a->do_after_signal = NULL;
	a->do_tick = NULL;
}
