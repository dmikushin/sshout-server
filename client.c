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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>

#define MAX(A,B) ((A)>(B)?(A):(B))
#define REMOTE_MODE_DIRECT 1
#define REMOTE_MODE_API 2

static void print_with_time(time_t t, const char *format, ...) {
	va_list ap;
	struct tm tm;
	if(t == -1) t = time(NULL);
	localtime_r(&t, &tm);
	printf("\r[%.2d:%.2d:%.2d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	putchar('\n');
}

static int send_login(int fd, const char *orig_user_name, const char *client_address) {
	int r = 0;
	size_t user_name_len = strlen(orig_user_name);
	//char user_name[USER_NAME_MAX_LENGTH];
	if(user_name_len > USER_NAME_MAX_LENGTH - 1) user_name_len = USER_NAME_MAX_LENGTH - 1;
	//memcpy(user_name, orig_user_name, user_name_len);
	//memset(user_name + user_name_len, 0, USER_NAME_MAX_LENGTH - user_name_len);
	const char *space = strchr(client_address, ' ');
	size_t host_name_len = space ? space - client_address : strlen(client_address);
	if(host_name_len > HOST_NAME_MAX_LENGTH) host_name_len = HOST_NAME_MAX_LENGTH;
	//char host_name[host_name_len + 1];
	//memcpy(host_name, client_address, host_name_len);
	//host_name[host_name_len] = 0;
	size_t packet_len = sizeof(struct local_packet) + USER_NAME_MAX_LENGTH + host_name_len;
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

int client_mode(const struct sockaddr_un *socket_addr, const char *user_name) {
	int remote_mode = REMOTE_MODE_DIRECT;
	const char *client_address = getenv("SSH_CLIENT");
	if(!client_address) {
		fputs("client mode can only be used in a SSH session\n", stderr);
		return 1;
	}
	const char *command = getenv("SSH_ORIGINAL_COMMAND");
	if(command) {
		if(strcmp(command, "api") == 0) remote_mode = REMOTE_MODE_API;
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

	if(remote_mode != REMOTE_MODE_DIRECT) {
		fputs("This remote mode is currently not implemented\n", stderr);
		return 1;
	}

	send_login(fd, user_name, client_address);

	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	FD_SET(STDIN_FILENO, &fdset);
	int maxfd = MAX(fd, STDIN_FILENO);
	setvbuf(stdout, NULL, _IOLBF, 0);

	while(1) {
		fd_set rfdset = fdset;
		if(select(maxfd + 1, &rfdset, NULL, NULL, NULL) < 0) {
			if(errno == EINTR) continue;
			perror("select");
		}
		if(FD_ISSET(fd, &rfdset)) {
			struct local_packet *packet;
			switch(get_local_packet(fd, &packet)) {
				case GET_PACKET_EOF:
					print_with_time(-1, "Server closed connection");
					close(fd);
					return 0;
				case GET_PACKET_ERROR:
					perror("read");
					close(fd);
					return 1;
				case GET_PACKET_SHORT_READ:
					print_with_time(-1, "Packet short read");
					close(fd);
					return 1;
				case GET_PACKET_TOO_LARGE:
					print_with_time(-1, "Packet too large");
					close(fd);
					return 1;
				case GET_PACKET_OUT_OF_MEMORY:
					print_with_time(-1, "Out of memory");
					close(fd);
					return 1;
				case 0:
					break;
				default:
					print_with_time(-1, "Internal error");
					abort();
			}
			switch(packet->type) {
				case SSHOUT_LOCAL_STATUS:
					break;
				case SSHOUT_LOCAL_DISPATCH_MESSAGE:
					break;
				case SSHOUT_LOCAL_ONLINE_USERS_INFO:
					break;
				default:
					print_with_time(-1, "Unknown packet type %d", packet->type);
					break;
			}
			free(packet);
		}
		if(FD_ISSET(STDIN_FILENO, &fdset)) {
			char *line = readline(NULL);
			if(!line) {
				print_with_time(-1, "Exiting ...");
				return 0;
			}
			if(*line == '/') {
				print_with_time(-1, "command ...");
			} else {
				print_with_time(-1, "send msg '%s' ...", line);
			}
			free(line);
		}
	}
}
