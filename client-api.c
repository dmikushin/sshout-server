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

/* This part is actually the API server; it is named 'client' because it is
 * the client of the local daemon sshoutd(8) */

#include "common.h"
#include "client.h"
#include "api.h"
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>

static void send_api_pass(int version) {
	uint32_t length = 1 + 6 + 2;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_pass: out of memory");
		exit(1);
	}
	packet->length = htonl(length);
	packet->type = htons(SSHOUT_API_PASS);
	memcpy(packet->data, "SSHOUT", 6);
	*(uint16_t *)(packet->data + 6) = htons(version);
	while(write(STDOUT_FILENO, packet, 4 + length) < 0) {
		if(errno == EINTR) continue;
		syslog(LOG_ERR, "send_api_pass: write: STDOUT_FILENO: errno %d", errno);
		exit(1);
	}
	free(packet);
}

static void send_api_error(int code, const char *message) {
}

static void send_api_message(struct local_message *local_message) {
}

static void send_api_online_users(struct local_online_users_info *local_info) {
	uint32_t length = 1 + 2 + 2;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_online_users: out of memory");
		//return;
		exit(1);
	}
	packet->type = htons(SSHOUT_API_ONLINE_USERS_INFO);
	uint8_t *p = packet->data;
	*(uint16_t *)p = htons(local_info->your_id);
	p += 2;
	*(uint16_t *)p = htons(local_info->count);
	p += 2;
	int i = 0;
	while(i < local_info->count) {
		const struct local_online_user *u = local_info->user + i++;
		uint8_t user_name_len = strnlen(u->user_name, USER_NAME_MAX_LENGTH);
		uint8_t host_name_len = strnlen(u->host_name, HOST_NAME_MAX_LENGTH);
		length += 2 + 1 + user_name_len + 1 + host_name_len;
		packet = realloc(packet, 4 + length);
		if(!packet) {
			syslog(LOG_ERR, "send_api_online_users: out of memory");
			exit(1);
		}
		*(uint16_t *)p = htons(u->id);
		p += 2;
		*(uint8_t *)p = user_name_len;
		p += 4;
		memcpy(p, u->user_name, user_name_len);
		p += user_name_len;
		*(uint8_t *)p = host_name_len;
		p += 4;
		memcpy(p, u->host_name, host_name_len);
		p += host_name_len;
	}
	packet->length = htonl(length);
	while(write(STDOUT_FILENO, packet, 4 + length) < 0) {
		if(errno == EINTR) continue;
		//r = -1;
		//break;
		syslog(LOG_ERR, "send_api_online_users: write: STDOUT_FILENO: errno %d", errno);
		exit(1);
	}
	free(packet);
}

static void send_api_user_state(const char *user, int online) {
}

static int api_version = 0;

static char *syslog_ident;

static void client_api_init_io(const char *user_name) {
	//char ident[8 + USER_NAME_MAX_LENGTH + 4 + 1];
	size_t len = 8 + USER_NAME_MAX_LENGTH + 4 + 1;
	syslog_ident = malloc(len);
	if(!syslog_ident) {
		perror("malloc");
		exit(1);
	}
	snprintf(syslog_ident, len, "sshoutd:%s:api", user_name);
	openlog(syslog_ident, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "API server started");
}

static void client_api_do_local_packet(int fd) {
	if(!api_version) {
		// XXX
		sleep(1);
		return;
	}
	struct local_packet *packet;
	int e = get_local_packet(fd, &packet);
	switch(e) {
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
			syslog(LOG_ERR, "Unknown error %d from get_local_packet", e);
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
		case GET_PACKET_TOO_SMALL:
			syslog(LOG_ERR, "Received API packet too small");
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
	// packet->type have only 1 byte, doesn't need to convert byte order
	if(!api_version && packet->type != SSHOUT_API_HELLO) {
		syslog(LOG_ERR, "Received API packet type %hhu before handshake", ntohs(packet->type));
		close(fd);
		exit(1);
	}
	switch(packet->type) {
		case SSHOUT_API_HELLO:
			if(memcmp(packet->data, "SSHOUT", 6)) {
				syslog(LOG_ERR, "SSHOUT_API_HELLO: handshake failed, magic isn't match");
				close(fd);
				exit(1);
			}
			api_version = ntohs(*(uint16_t *)(packet->data + 6));
			if(api_version != 1) {
				syslog(LOG_ERR, "SSHOUT_API_HELLO: handshake failed, unsupported API version %hu",
					(unsigned short int)api_version);
				close(fd);
				exit(1);
			}
			send_api_pass(1);
			break;
		case SSHOUT_API_GET_ONLINE_USER:
			if(client_send_request_get_online_users(fd) < 0) {
				syslog(LOG_ERR,
					"SSHOUT_API_GET_ONLINE_USER: client_send_request_get_online_users failed, errno %d",
					errno);
				break;
			}
			break;
		case SSHOUT_API_SEND_MESSAGE:
			break;
		default:
			syslog(LOG_ERR, "Received unknown API packet type %hhu", ntohs(packet->type));
			break;
	}
	free(packet);
}

void client_api_get_actions(struct client_backend_actions *a) {
	a->init_io = client_api_init_io;
	a->do_local_packet = client_api_do_local_packet;
	a->do_stdin = client_api_do_stdin;
	a->do_after_signal = NULL;
	a->do_tick = NULL;
}
