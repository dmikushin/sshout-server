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
#include <string.h>
#include <stdio.h>
#include <errno.h>

int server_mode(const char *home) {
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	size_t home_len = strlen(home);
	if(home_len + 1 + sizeof SOCKET_NAME > sizeof addr.sun_path) {
		fprintf(stderr, "home path too long (%zu bytes)\n", home_len);
		return 1;
	}
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		perror("socket");
		return 1;
	}
	if(chdir(home) < 0) perror(home);
	//char socket_path[home_len + 1 + sizeof SOCKET_NAME];
	memcpy(addr.sun_path, home, home_len);
	addr.sun_path[home_len] = '/';
	memcpy(addr.sun_path + home_len + 1, SOCKET_NAME, sizeof SOCKET_NAME);
	unlink(addr.sun_path);
	if(bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		perror(addr.sun_path);
		close(fd);
		return 1;
	}
	if(fchmod(fd, 0600) < 0) {
		perror("fchmod");
		close(fd);
		unlink(addr.sun_path);
		return 1;
	}
	if(listen(fd, 64) < 0) {
		perror("listen");
		close(fd);
		unlink(addr.sun_path);
		return 1;
	}

	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	int maxfd = fd;

	int client_fds[FD_SETSIZE];
	int i;
	for(i=0; i<FD_SETSIZE; i++) client_fds[i] = -1;

	while(1) {
		fd_set rfdset = fdset;
		int n = select(maxfd + 1, &rfdset, NULL, NULL, NULL);
		if(n < 0) {
			if(errno == EINTR) continue;
			perror("select");
			return 1;
		}
		if(FD_ISSET(fd, &rfdset)) {
			struct sockaddr_un client_addr;
			socklen_t addr_len = sizeof client_addr;
			int cfd;
			do {
				cfd = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
			} while(cfd == -1 && errno == EINTR);
			if(cfd == -1) {
				perror("accept");
				//if(errno == EMFILE) continue;
				//return 1;
				//continue;
				if(errno == EMFILE && n < 2) sleep(1);
			} else {
				fprintf(stderr, "client fd %d\n", cfd);
/*
				for(i = 0; client_fds[i] != -1; i++) {
				}
*/
				i = 0;
				while(1) {
					if(i >= FD_SETSIZE) {
						fprintf(stderr, "warning: cannot add fd %d to set, too many clients\n", cfd);
						close(cfd);
						break;
					}
					if(client_fds[i] == -1) {
						client_fds[i] = cfd;
						FD_SET(cfd, &fdset);
						if(cfd > maxfd) maxfd = cfd;
						fprintf(stderr, "client %d fd %d\n", i, cfd);
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
				// TODO: read msg
			}
		}
	}
}
