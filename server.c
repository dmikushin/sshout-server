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
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

static struct local_online_user online_users[FD_SETSIZE];

static void syslog_perror(const char *ident) {
	int e = errno;
	syslog(LOG_ERR, "%s: %s (%d)", ident, strerror(e), e);
}

static int user_online(int id, const char *user_name, const char *host_name, int *index) {
	int i = 0;
	while(online_users[i].id != -1) {
		if(++i >= sizeof online_users / sizeof *online_users) {
			syslog(LOG_WARNING, "cannot let user '%s' from %s login: too many users\n", user_name, host_name);
			return -1;
		}
	}
	struct local_online_user *p = online_users + i;
	p->id = id;
	strncpy(p->user_name, user_name, sizeof p->user_name);
	strncpy(p->host_name, user_name, sizeof p->host_name);
	return 0;
}

static void user_offline(int id) {
	int i = 0;
	while(online_users[i].id != id) {
		if(++i >= sizeof online_users / sizeof *online_users) return;
	}
	online_users[i].id = -1;
}

static void send_online_users(int receiver_id, int receiver_fd) {
	int i = 0, count = 0;
	do {
		if(online_users[i].id != -1) count++;
	} while(++i < sizeof online_users / sizeof *online_users);
	size_t packet_length = sizeof(struct local_packet) + sizeof(struct local_online_users_info) + sizeof(struct local_online_user) * count;
	struct local_packet *packet = malloc(packet_length);
	if(!packet) {
		syslog(LOG_ERR, "send_online_users: out of memory");
		return;
	}
	packet->length = packet_length - sizeof packet->length;
	packet->type = SSHOUT_LOCAL_ONLINE_USERS_INFO;
	struct local_online_users_info *info = (struct local_online_users_info *)packet->data;
	info->your_id = receiver_id;
	info->count = count;
	i = 0;
	for(i = 0; i < sizeof online_users / sizeof *online_users && count > 0; i++) {
		if(online_users[i].id == -1) continue;
		count--;
		memcpy(info + count, online_users + i, sizeof(struct local_online_user));
	}
	while(write(receiver_fd, packet, packet_length) < 0) {
		if(errno == EINTR) continue;
		syslog_perror("send_online_users: write");
		break;
	}
	free(packet);
}

int server_mode(const struct sockaddr_un *socket_addr) {
	static const struct timeval timeout = { .tv_sec = 2 };

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		perror("socket");
		return 1;
	}
	//if(fcntl(fd, F_SETFL, O_NONBLOCK) < 0) syslog_perror("fcntl");
	unlink(socket_addr->sun_path);
	if(bind(fd, (struct sockaddr *)socket_addr, sizeof(struct sockaddr_un)) < 0) {
		perror(socket_addr->sun_path);
		close(fd);
		return 1;
	}
	if(chmod(socket_addr->sun_path, 0600) < 0) {
		perror(socket_addr->sun_path);
		close(fd);
		unlink(socket_addr->sun_path);
		return 1;
	}
	if(listen(fd, 64) < 0) {
		perror("listen");
		close(fd);
		unlink(socket_addr->sun_path);
		return 1;
	}

	openlog("sshoutd", LOG_PID | LOG_PERROR, LOG_DAEMON);

	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	int max_fd = fd;

	int client_fds[FD_SETSIZE];
	int online_users_indexes[FD_SETSIZE];
	int i;
	for(i=0; i<FD_SETSIZE; i++) {
		client_fds[i] = -1;
		online_users[i].id = -1;
		online_users_indexes[i] = -1;
	}

/*
	char *buffer = malloc(LOCAL_PACKET_BUFFER_SIZE);
	if(!buffer) {
		perror("malloc");
		return 1;
	}
*/

	while(1) {
		int have_client_fd_closed = 0;
		fd_set rfdset = fdset;
		int n = select(max_fd + 1, &rfdset, NULL, NULL, NULL);
		if(n < 0) {
			if(errno == EINTR) continue;
			syslog_perror("select");
		}
		if(FD_ISSET(fd, &rfdset)) {
			struct sockaddr_un client_addr;
			socklen_t addr_len = sizeof client_addr;
			int cfd;
			do {
				cfd = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
			} while(cfd == -1 && errno == EINTR);
			if(cfd == -1) {
				syslog_perror("accept");
				//if(errno == EMFILE) continue;
				//return 1;
				//continue;
				if(errno == EMFILE && n < 2) sleep(1);
			} else {
				syslog(LOG_INFO, "client fd %d\n", cfd);
			        if(setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) syslog_perror("setsockopt");
			        if(setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) syslog_perror("setsockopt");
				i = 0;
				while(1) {
					if(i >= FD_SETSIZE) {
						syslog(LOG_WARNING, "cannot add fd %d to set, too many clients\n", cfd);
						close(cfd);
						break;
					}
					if(client_fds[i] == -1) {
						client_fds[i] = cfd;
						FD_SET(cfd, &fdset);
						if(cfd > max_fd) max_fd = cfd;
						syslog(LOG_INFO, "client %d fd %d\n", i, cfd);
						break;
					}
					i++;
				}
			}
			n--;
		}
		for(i=0; n && i<FD_SETSIZE; i++) {
			int cfd = client_fds[i];
			if(cfd == -1) continue;
			if(FD_ISSET(cfd, &rfdset)) {
				n--;
				struct local_packet *packet;
				switch(get_local_packet(cfd, &packet)) {
					case GET_PACKET_EOF:
						syslog(LOG_INFO, "client %d fd %d EOF\n", i, cfd);
						goto end_of_connection;
					case GET_PACKET_ERROR:
						syslog_perror("read");
						goto end_of_connection;
					case GET_PACKET_SHORT_READ:
						syslog(LOG_INFO, "client %d fd %d short read\n", i, cfd);
						goto end_of_connection;
					case GET_PACKET_TOO_LARGE:
						syslog(LOG_WARNING, "client %d fd %d packet too large (%u bytes)\n",
							i, cfd, *(unsigned int *)packet);
						goto end_of_connection;
					case GET_PACKET_OUT_OF_MEMORY:
						syslog(LOG_WARNING, "client %d fd %d out of memory (allocating %u bytes)\n",
							i, cfd, *(unsigned int *)packet);
						goto end_of_connection;
					case 0:
						break;
					default:
						syslog(LOG_INFO, "client %d fd %d unknown error\n", i, cfd);
						//abort();
						goto end_of_connection;
				}
				switch(packet->type) {
					case SSHOUT_LOCAL_LOGIN:
						user_online(i, packet->data, packet->data + USER_NAME_MAX_LENGTH, online_users_indexes + i);
						break;
					case SSHOUT_LOCAL_POST_MESSAGE:
						if(online_users_indexes[i] == -1) {
							syslog(LOG_INFO, "client %d fd %d posting message without login", i, cfd);
							break;
						}
						// TODO
						break;
					case SSHOUT_LOCAL_GET_ONLINE_USERS:
						send_online_users(i, cfd);
						break;
					default:
						syslog(LOG_NOTICE, "client %d fd %d unknown packet type %d",
							i, cfd, packet->type);
						break;
				}
				free(packet);
				continue;
end_of_connection:
				close(cfd);
				FD_CLR(cfd, &fdset);
				have_client_fd_closed = 1;
				user_offline(i);
				online_users_indexes[i] = -1;
			}
		}
		if(have_client_fd_closed) {
			max_fd = fd;
			for(i=0; n && i<FD_SETSIZE; i++) if(client_fds[i] > max_fd) max_fd = client_fds[i];
		}
	}
}
