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
#include "misc.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "syncrw.h"
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#define MAX(A,B) ((A)>(B)?(A):(B))
#define REMOTE_MODE_CLI 1
#define REMOTE_MODE_API 2
#define REMOTE_MODE_LOG 3
#define REMOTE_MODE_IRC 4

static int send_login(int fd, const char *orig_user_name, const char *client_address) {
	int r = 0;
	size_t user_name_len = strlen(orig_user_name);
	//char user_name[USER_NAME_MAX_LENGTH];
	if(user_name_len > USER_NAME_MAX_LENGTH - 1) user_name_len = USER_NAME_MAX_LENGTH - 1;
	//memcpy(user_name, orig_user_name, user_name_len);
	//memset(user_name + user_name_len, 0, USER_NAME_MAX_LENGTH - user_name_len);
	const char *space = strchr(client_address, ' ');
	size_t host_name_len = space ? space - client_address : strlen(client_address);
	if(host_name_len > HOST_NAME_MAX_LENGTH - 1) host_name_len = HOST_NAME_MAX_LENGTH - 1;
	//char host_name[host_name_len + 1];
	//memcpy(host_name, client_address, host_name_len);
	//host_name[host_name_len] = 0;
	size_t packet_len = sizeof(struct local_packet) + USER_NAME_MAX_LENGTH + host_name_len + 1;
	struct local_packet *packet = malloc(packet_len);
	if(!packet) return -1;
	packet->length = packet_len - sizeof packet->length;
	packet->type = SSHOUT_LOCAL_LOGIN;
	memcpy(packet->data, orig_user_name, user_name_len);
	memset(packet->data + user_name_len, 0, USER_NAME_MAX_LENGTH - user_name_len);
	char *host_name = packet->data + USER_NAME_MAX_LENGTH;
	memcpy(host_name, client_address, host_name_len);
	host_name[host_name_len] = 0;
	while(write(fd, packet, packet_len) < 0) {
		if(errno == EINTR) continue;
		r = -1;
		break;
	}
	int e = errno;
	free(packet);
	errno = e;
	return r;
}

int client_send_request_get_online_users(int fd) {
	struct local_packet packet;
	packet.length = sizeof packet - sizeof packet.length;
	packet.type = SSHOUT_LOCAL_GET_ONLINE_USERS;
	while(write(fd, &packet, sizeof packet) < 0) {
		if(errno == EINTR) continue;
		return -1;
	}
	return 0;
}

// field msg_from is not needed
int client_post_message(int fd, const struct local_message *message) {
	int r = 0;
	size_t packet_len = sizeof(struct local_packet) + sizeof(struct local_message) + message->msg_length;
	if(packet_len < message->msg_length) {
#ifdef EOVERFLOW
		errno = EOVERFLOW;
#else
		errno = EINVAL;
#endif
		return -1;
	}
	struct local_packet *packet = malloc(packet_len);
	if(!packet) return -1;
	packet->length = packet_len - sizeof packet->length;
	packet->type = SSHOUT_LOCAL_POST_MESSAGE;
	memcpy(packet->data, message, sizeof(struct local_message) + message->msg_length);
	if(sync_write(fd, packet, packet_len) < 0) {
		r = -1;
	}
	int e = errno;
	free(packet);
	errno = e;
	return r;
}

int client_post_plain_text_message(int fd, const char *receiver, const char *text) {
	size_t receiver_len = strlen(receiver);
	size_t text_len = strlen(text);
	struct local_message *message = malloc(sizeof(struct local_message) + text_len);
	if(!message) return -1;
	if(receiver_len > USER_NAME_MAX_LENGTH - 1) receiver_len = USER_NAME_MAX_LENGTH - 1;
	memcpy(message->msg_to, receiver, receiver_len);
	message->msg_to[receiver_len] = 0;
	message->msg_type = SSHOUT_MSG_PLAIN;
	message->msg_length = text_len;
	memcpy(message->msg, text, text_len);
	int r = client_post_message(fd, message);
	free(message);
	return r;
}

static int local_socket = -1;

int client_get_local_socket_fd() {
	return local_socket;
}

int client_mode(const struct sockaddr_un *socket_addr, const char *user_name) {
	pid_t ppid = getppid();
	int remote_mode = REMOTE_MODE_CLI;
	const char *client_address = getenv("SSH_CLIENT");
	if(!client_address) {
		fputs("client mode can only be used in a SSH session\n", stderr);
		return 1;
	}
	if(!is_valid_user_name(user_name)) {
		fprintf(stderr, "Invalid user name '%s'\n", user_name);
		return 1;
	}
	const char *command = getenv("SSH_ORIGINAL_COMMAND");
	if(command) {
		if(strcmp(command, "cli") == 0) remote_mode = REMOTE_MODE_CLI;
		else if(strcmp(command, "api") == 0) remote_mode = REMOTE_MODE_API;
		else if(strcmp(command, "log") == 0) remote_mode = REMOTE_MODE_LOG;
#ifdef ENABLE_IRC_FRONTEND
		else if(strcmp(command, "irc") == 0) remote_mode = REMOTE_MODE_IRC;
#endif
		else {
			fprintf(stderr, "Command '%s' is not recognized\n", command);
			return 1;
		}
	}
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		perror("socket");
		return 1;
	}
	while(connect(fd, (struct sockaddr *)socket_addr, sizeof(struct sockaddr_un)) < 0) {
		if(errno == EINTR) continue;
		perror("connect");
		return 1;
	}

	send_login(fd, user_name, client_address);

	struct timeval timeout = { .tv_sec = 60 };
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	int max_fd;
	if(remote_mode == REMOTE_MODE_LOG) {
		max_fd = fd;
		close(STDIN_FILENO);
		if(open("/dev/null", O_RDONLY) != 0) {
			fputs("Cannot open /dev/null for read as fd 0\n", stderr);
			return 1;
		}
	} else {
		FD_SET(STDIN_FILENO, &fdset);
		max_fd = MAX(fd, STDIN_FILENO);
	}

	struct client_frontend_actions actions;
	switch(remote_mode) {
		case REMOTE_MODE_CLI:
			client_cli_get_actions(&actions, 0);
			break;
		case REMOTE_MODE_API:
			client_api_get_actions(&actions);
			break;
		case REMOTE_MODE_LOG:
			client_cli_get_actions(&actions, 1);
			break;
#ifdef ENABLE_IRC_FRONTEND
		case REMOTE_MODE_IRC:
			client_irc_get_actions(&actions);
			break;
#endif
	}
	actions.init_io(user_name);
	local_socket = fd;

	while(getppid() == ppid) {
		fd_set rfdset = fdset;
		struct timeval current_timeout = timeout;
		int n = select(max_fd + 1, &rfdset, NULL, NULL, &current_timeout);
		if(n < 0) {
			if(errno == EINTR) {
				if(actions.do_after_signal) actions.do_after_signal();
				continue;
			}
			perror("select");
			return 1;
		}
		if(actions.do_tick) actions.do_tick();
		if(n) {
			if(FD_ISSET(fd, &rfdset)) actions.do_local_packet(fd);
			if(FD_ISSET(STDIN_FILENO, &rfdset)) actions.do_stdin(fd);
		}
	}

	fputs("Parent process changed, exiting\n", stderr);
	return 0;
}
