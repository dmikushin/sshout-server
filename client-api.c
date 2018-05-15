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
#include "syncrw.h"
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#define hton64(a) (htons(1) == 1 ? (a) : ((uint64_t)htonl((a) & 0xFFFFFFFF) << 32) | htonl((a) >> 32))

static void send_api_pass(int version) {
	uint32_t length = 1 + 6 + 2;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_pass: out of memory");
		exit(1);
	}
	packet->length = htonl(length);
	packet->type = SSHOUT_API_PASS;
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
	uint32_t message_length = strlen(message);
	uint32_t length = 1 + 4 + 4 + message_length;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_error: out of memory");
		exit(1);
	}
	packet->length = htonl(length);
	packet->type = SSHOUT_API_ERROR;
	*(uint32_t *)packet->data = htonl(code);
	*(uint32_t *)(packet->data + 4) = htonl(message_length);
	memcpy(packet->data + 8, message, message_length);
	while(write(STDOUT_FILENO, packet, 4 + length) < 0) {
		if(errno == EINTR) continue;
		syslog(LOG_ERR, "send_api_error: write: STDOUT_FILENO: errno %d", errno);
		exit(1);
	}
	free(packet);
}

static void send_api_message(struct local_message *local_message) {
	uint8_t from_user_name_len = strnlen(local_message->msg_from, USER_NAME_MAX_LENGTH);
	uint8_t to_user_name_len = strnlen(local_message->msg_to, USER_NAME_MAX_LENGTH);
	uint32_t length = 1 + 8 + 1 + from_user_name_len + 1 + to_user_name_len + 1 + 4 + local_message->msg_length;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_message: out of memory");
		exit(1);
	}
	packet->length = htonl(length);
	packet->type = SSHOUT_API_RECEIVE_MESSAGE;
	uint8_t *p = packet->data;
	uint64_t t = time(NULL);
	*(uint64_t *)p = hton64(t);
	p += 8;
	*p++ = from_user_name_len;
	memcpy(p, local_message->msg_from, from_user_name_len);
	p += from_user_name_len;
	*p++ = to_user_name_len;
	memcpy(p, local_message->msg_to, to_user_name_len);
	p += to_user_name_len;
	switch(local_message->msg_type) {
		case SSHOUT_MSG_PLAIN:
			*p = SSHOUT_API_MESSAGE_TYPE_PLAIN;
			break;
		case SSHOUT_MSG_RICH:
			*p = SSHOUT_API_MESSAGE_TYPE_RICH;
			break;
		case SSHOUT_MSG_IMAGE:
			*p = SSHOUT_API_MESSAGE_TYPE_IMAGE;
			break;
	}
	p++;
	*(uint32_t *)p = local_message->msg_length;
	p += 4;
	memcpy(p, local_message->msg, local_message->msg_length);
	while(write(STDOUT_FILENO, packet, 4 + length) < 0) {
		if(errno == EINTR) continue;
		syslog(LOG_ERR, "send_api_message: write: STDOUT_FILENO: errno %d", errno);
		exit(1);
	}
	free(packet);
}

static void send_api_online_users(struct local_online_users_info *local_info) {
	uint32_t length = 1 + 2 + 2;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_online_users: out of memory");
		//return;
		exit(1);
	}
	packet->type = SSHOUT_API_ONLINE_USERS_INFO;
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
		uint8_t *np = realloc(packet, 4 + length);
		if(!np) {
			syslog(LOG_ERR, "send_api_online_users: out of memory");
			exit(1);
		}
		//p = np + (p - (uint8_t *)packet);
		p += np - (uint8_t *)packet;
		packet = (struct sshout_api_packet *)np;
		*(uint16_t *)p = htons(u->id);
		p += 2;
		*p++ = user_name_len;
		memcpy(p, u->user_name, user_name_len);
		p += user_name_len;
		*p++ = host_name_len;
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
	uint8_t user_name_len = strnlen(user, USER_NAME_MAX_LENGTH);
	uint32_t length = 1 + 1 + user_name_len;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_user_state: out of memory");
		exit(1);
	}
	packet->type = SSHOUT_API_USER_STATE_CHANGE;
	packet->data[0] = (uint8_t)online;
	packet->data[1] = user_name_len;
	memcpy(packet->data + 2, user, user_name_len);
	while(write(STDOUT_FILENO, packet, 4 + length) < 0) {
		if(errno == EINTR) continue;
		syslog(LOG_ERR, "send_api_user_state: write: STDOUT_FILENO: errno %d", errno);
		exit(1);
	}
	free(packet);
}

static int send_api_motd() {
	char buffer[4096];
	int fd = open(SSHOUT_MOTD_FILE, O_RDONLY);
	if(fd == -1) {
		int e = errno;
		if(e != ENOENT) syslog(LOG_WARNING, "send_api_motd: " SSHOUT_MOTD_FILE ": %s", strerror(e));
		errno = e;
		return -1;
	}
	int s = sync_read(fd, buffer, sizeof buffer);
	if(s < 0) {
		int e = errno;
		if(e != ENOENT) syslog(LOG_WARNING, "send_api_motd: read: %s", strerror(e));
		errno = e;
		return -1;
	}
	if(!s) return -1;

	uint32_t length = 1 + 4 + s;
	struct sshout_api_packet *packet = malloc(4 + length);
	if(!packet) {
		syslog(LOG_ERR, "send_api_motd: out of memory");
		exit(1);
	}
	packet->length = htonl(length);
	packet->type = SSHOUT_API_MOTD;
	*(uint32_t *)packet->data = s;
	memcpy(packet->data + 4, buffer, s);
	while(write(STDOUT_FILENO, packet, 4 + length) < 0) {
		if(errno == EINTR) continue;
		syslog(LOG_ERR, "send_api_motd: write: STDOUT_FILENO: errno %d", errno);
		exit(1);
	}
	free(packet);
	return 0;
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

static int post_message_from_raw_api_data(int fd, uint8_t *p, uint32_t data_length) {
	size_t receiver_len = *p++;
	if(receiver_len > data_length - 6) return -1;
	void *receiver_p = p;
	p += receiver_len;
	enum local_msg_type t = *p++;
	size_t text_len = *(uint32_t *)p;
	p += 4;
	if(receiver_len + text_len > data_length - 6) return -1;
	struct local_message *message = malloc(sizeof(struct local_message) + text_len);
	if(!message) return -1;
	if(receiver_len > USER_NAME_MAX_LENGTH - 1) receiver_len = USER_NAME_MAX_LENGTH - 1;
	memcpy(message->msg_to, receiver_p, receiver_len);
	message->msg_to[receiver_len] = 0;
	message->msg_type = t;
	message->msg_length = text_len;
	memcpy(message->msg, p, text_len);
	int r = client_post_message(fd, message);
	free(message);
	return r;
}

static void client_api_do_stdin(int fd) {
	struct sshout_api_packet *packet;
	uint32_t length;
	int e = get_api_packet(STDIN_FILENO, &packet, &length, 1);
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
			if(length != 9) {
				syslog(LOG_ERR, "SSHOUT_API_HELLO: handshake failed, packet length mismatch (%u != 9)",
					(unsigned int)length);
				close(fd);
				exit(1);
			}
			if(memcmp(packet->data, "SSHOUT", 6)) {
				syslog(LOG_ERR, "SSHOUT_API_HELLO: handshake failed, magic mismatch");
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
			send_api_motd();
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
			post_message_from_raw_api_data(fd, packet->data, length - 1);
			break;
		case SSHOUT_API_GET_MOTD:
			errno = ENOENT;
			if(send_api_motd() < 0) {
				send_api_error(SSHOUT_API_ERROR_MOTD_NOT_AVAILABLE,
					errno == ENOENT ? "No MOTD" : strerror(errno));
			}
			break;
		default:
			syslog(LOG_ERR, "Received unknown API packet type %hhu", ntohs(packet->type));
			break;
	}
	free(packet);
}

void client_api_get_actions(struct client_frontend_actions *a) {
	a->init_io = client_api_init_io;
	a->do_local_packet = client_api_do_local_packet;
	a->do_stdin = client_api_do_stdin;
	a->do_after_signal = NULL;
	a->do_tick = NULL;
}