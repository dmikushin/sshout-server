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
#include <stdio.h>
#include <errno.h>

#define LOCAL_PACKET_BUFFER_SIZE (512 * 1024)

static struct online_user {
	int id;
	char user_name[USER_NAME_MAX_LENGTH];
	char host_name[128];
} online_users[FD_SETSIZE];

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
	struct online_user *p = online_users + i;
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

int server_mode(const struct sockaddr_un *socket_addr) {
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(fd == -1) {
		perror("socket");
		return 1;
	}
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
	int maxfd = fd;

	int client_fds[FD_SETSIZE];
	int online_users_indexes[FD_SETSIZE];
	int i;
	for(i=0; i<FD_SETSIZE; i++) {
		client_fds[i] = -1;
		online_users[i].id = -1;
		online_users_indexes[i] = -1;
	}

	char *buffer = malloc(LOCAL_PACKET_BUFFER_SIZE);
	if(!buffer) {
		perror("malloc");
		return 1;
	}

	while(1) {
		fd_set rfdset = fdset;
		int n = select(maxfd + 1, &rfdset, NULL, NULL, NULL);
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
/*
				for(i = 0; client_fds[i] != -1; i++) {
				}
*/
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
						if(cfd > maxfd) maxfd = cfd;
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
				//uint16_t packet_type;
				int s;
				do {
					s = read(cfd, buffer, LOCAL_PACKET_BUFFER_SIZE);
				} while(s < 0 && errno == EINTR);
				if(s < 0) {
					syslog_perror("read");
					close(fd);
					user_offline(i);
					online_users_indexes[i] = -1;
					continue;
				}
				if(!s) {
					syslog(LOG_INFO, "client %d fd %d EOF\n", i, cfd);
					close(fd);
					user_offline(i);
					online_users_indexes[i] = -1;
					continue;
				}
				if(s < 2) {
					syslog(LOG_INFO, "client %d fd %d packet too short\n", i, cfd);
					close(fd);
					user_offline(i);
					online_users_indexes[i] = -1;
					continue;
				}
				switch(*(uint8_t *)buffer) {
					case SSHOUT_LOCAL_LOGIN:
						user_online(i, buffer + sizeof(uint8_t), buffer + sizeof(uint8_t) + USER_NAME_MAX_LENGTH, online_users_indexes + i);
						break;
					case SSHOUT_LOCAL_POST_MESSAGE:
						if(online_users_indexes[i] == -1) {
							syslog(LOG_INFO, "client %d fd %d posting message withoutn login", i, cfd);
							break;
						}
						// TODO
						break;
					case SSHOUT_LOCAL_GET_ONLINE_USERS:
						//send_online_users(i, cfd);
						break;
				}
			}
		}
	}
}
