/* Secure Shout Host Oriented Unified Talk
 * Copyright 2015-2023 Rivoreo
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

#if defined __sun && defined __SVR4
#define HAVE_GETPEERUCRED
#endif

#define _GNU_SOURCE
#include "common.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include "syncrw.h"
#include <syslog.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include "file-helpers.h"
#include <signal.h>
#ifdef HAVE_UPDWTMPX
#include <utmpx.h>
#ifdef HAVE_GETPEERUCRED
#include <ucred.h>
#endif
#endif
#ifdef HAVE_ICONV
#include <iconv.h>
#endif

static char user_names[FD_SETSIZE][USER_NAME_MAX_LENGTH];
static char user_client_addresses[FD_SETSIZE][HOST_NAME_MAX_LENGTH];
#ifdef HAVE_ICONV
static char *user_text_encodings[FD_SETSIZE];
#endif

static void syslog_perror(const char *format, ...) {
	int e = errno;
	char buffer[256];
	va_list ap;
	va_start(ap, format);
	vsnprintf(buffer, sizeof buffer, format, ap);
	syslog(LOG_ERR, "%s: %s (%d)", buffer, strerror(e), e);
	va_end(ap);
}

static void broadcast_user_state(const char *user_name, int on, const fd_set *client_fds, int fd_max_size) {
	size_t user_name_len = strnlen(user_name, USER_NAME_MAX_LENGTH - 1);
	size_t packet_len = sizeof(struct local_packet) + user_name_len + 1;
	struct local_packet *packet = malloc(packet_len);
	if(!packet) {
		syslog(LOG_ERR, "broadcast_user_state: out of memory");
		return;
	}
	packet->length = packet_len - sizeof packet->length;
	packet->type = on ? SSHOUT_LOCAL_USER_ONLINE : SSHOUT_LOCAL_USER_OFFLINE;
	memcpy(packet->data, user_name, user_name_len);
	packet->data[user_name_len] = 0;
	int fd = 0;
	do {
		if(!FD_ISSET(fd, client_fds)) continue;
		if(!*user_names[fd]) continue;
		while(write(fd, packet, packet_len) < 0) {
			if(errno == EINTR) continue;
			syslog_perror("broadcast_user_state: to %d: write", fd);
			break;
		}
	} while(++fd < fd_max_size);
	free(packet);
}

#ifdef HAVE_UPDWTMPX
static pid_t get_pid_from_unix_socket(int fd) {
#ifdef SO_PEERCRED
	struct ucred ucred;
	socklen_t len = sizeof ucred;
	if(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) return -1;
	return ucred.pid;
#elif defined HAVE_GETPEERUCRED
	ucred_t *ucred = NULL;
	if(getpeerucred(fd, &ucred) < 0) return -1;
	pid_t r = ucred_getpid(ucred);
	ucred_free(ucred);
	return r;
#else
	return -1;
#endif
}
#endif

static int user_online(int fd, const char *user_name, const char *host_name,
#ifdef HAVE_ICONV
  const char *text_encoding,
#endif
  const fd_set *client_fds, int fd_max_size) {
	int found_dup = 0;
	int i;
	for(i = 0; i < fd_max_size; i++) {
		if(i == fd) continue;
		if(!FD_ISSET(i, client_fds)) continue;
		if(strcmp(user_names[i], user_name) == 0) {
			found_dup = 1;
			break;
		}
	}
	size_t len = strnlen(user_name, USER_NAME_MAX_LENGTH - 1);
	memcpy(user_names[fd], user_name, len);
	user_names[fd][len] = 0;
	len = strnlen(host_name, HOST_NAME_MAX_LENGTH - 1);
	memcpy(user_client_addresses[fd], host_name, len);
	user_client_addresses[fd][len] = 0;
#ifdef HAVE_ICONV
	if(*text_encoding) user_text_encodings[fd] = strdup(text_encoding);
#endif
	syslog(LOG_INFO, "user %s login from %s fd %d dup %d", user_name, host_name, fd, found_dup);
#ifdef HAVE_UPDWTMPX
	if(access("wtmpx", W_OK) == 0) {
		struct timeval tv;
		if(gettimeofday(&tv, NULL) == 0) {
			pid_t pid = get_pid_from_unix_socket(fd);
			struct utmpx utx = {
				.ut_type = USER_PROCESS,
				.ut_pid = pid == -1 ? fd : pid,
				.ut_tv.tv_sec = tv.tv_sec,
				.ut_tv.tv_usec = tv.tv_usec
			};
			snprintf(utx.ut_line, sizeof utx.ut_line, "%d", fd);
			strncpy(utx.ut_user, user_name, sizeof utx.ut_user);
			strncpy(utx.ut_host, host_name, sizeof utx.ut_host);
			updwtmpx("wtmpx", &utx);
		}
	}
#endif
	if(!found_dup) broadcast_user_state(user_name, 1, client_fds, fd_max_size);
	return 0;
}

static void user_offline(int fd, const fd_set *client_fds, int fd_max_size) {
#ifdef HAVE_ICONV
	free(user_text_encodings[fd]);
	user_text_encodings[fd] = NULL;
#endif
	char *user_name = user_names[fd];
#ifdef HAVE_UPDWTMPX
	const char *host_name = user_client_addresses[fd];
#endif
	int found_dup = 0;
	int i = 0;
	while(i < fd_max_size) {
		if(i != fd && FD_ISSET(i, client_fds) && strcmp(user_names[i], user_name) == 0) {
			found_dup = 1;
			break;
		}
		i++;
	}
	if(!found_dup) broadcast_user_state(user_name, 0, client_fds, fd_max_size);
	syslog(LOG_INFO, "user %s logout fd %d dup %d", user_name, fd, found_dup);
#ifdef HAVE_UPDWTMPX
	if(access("wtmpx", W_OK) == 0) {
		struct timeval tv;
		if(gettimeofday(&tv, NULL) == 0) {
			pid_t pid = get_pid_from_unix_socket(fd);
			struct utmpx utx = {
				.ut_type = DEAD_PROCESS,
				.ut_pid = pid == -1 ? fd : pid,
				.ut_tv.tv_sec = tv.tv_sec,
				.ut_tv.tv_usec = tv.tv_usec
			};
			snprintf(utx.ut_line, sizeof utx.ut_line, "%d", fd);
			strncpy(utx.ut_user, user_name, sizeof utx.ut_user);
			strncpy(utx.ut_host, host_name, sizeof utx.ut_host);
			updwtmpx("wtmpx", &utx);
		}
	}
#endif
	*user_name = 0;
}

static int send_online_users(int receiver_fd, int fd_max_size) {
	int fd = 0, count = 0;
	do {
		if(*user_names[fd]) count++;
	} while(++fd < fd_max_size);
	size_t packet_length = sizeof(struct local_packet) + sizeof(struct local_online_users_info) + sizeof(struct local_online_user) * count;
	struct local_packet *packet = malloc(packet_length);
	if(!packet) {
		syslog(LOG_ERR, "send_online_users: out of memory");
		return 0;	// XXX
	}
	packet->length = packet_length - sizeof packet->length;
	packet->type = SSHOUT_LOCAL_ONLINE_USERS_INFO;
	struct local_online_users_info *info = (struct local_online_users_info *)packet->data;
	info->your_id = receiver_fd;
	info->count = count;
	for(fd = 0; fd < fd_max_size && count > 0; fd++) {
		if(!*user_names[fd]) continue;
		count--;
		struct local_online_user *p = info->user + count;
		p->id = fd;
		strcpy(p->user_name, user_names[fd]);
		strcpy(p->host_name, user_client_addresses[fd]);
	}
	int r = 0;
	if(sync_write(receiver_fd, packet, packet_length) < 0) {
		syslog_perror("send_online_users: write to %d", receiver_fd);
		r = -1;
	}
	free(packet);
	return r;
}

#ifdef HAVE_ICONV
static int convert_message(const char *from_encoding, const char *to_encoding, const char *sender_name, const struct local_message *msg, struct local_message **new_msg) {
	iconv_t cd = iconv_open(to_encoding, from_encoding);
	if(cd == (iconv_t)-1) return -1;
	*new_msg = malloc(sizeof(struct local_message) + msg->msg_length);
	if(!*new_msg) {
		iconv_close(cd);
		errno = ENOMEM;
		return -1;
	}
	(*new_msg)->msg_length = msg->msg_length;
	const char *input_p = msg->msg;
	size_t input_len = msg->msg_length;
	char *output_p = (*new_msg)->msg;
	size_t output_len = msg->msg_length;
	size_t len;
	while((len = iconv(cd, (char **)&input_p, &input_len, &output_p, &output_len)) == (size_t)-1) {
		int e = errno;
		if(e != E2BIG) {
			iconv_close(cd);
			free(*new_msg);
			errno = e;
			return -1;
		}
		(*new_msg)->msg_length += 32;
		struct local_message *p = realloc(*new_msg, sizeof(struct local_message) + (*new_msg)->msg_length);
		if(!p) {
			e = errno;
			iconv_close(cd);
			free(*new_msg);
			errno = e;
			return -1;
		}
		output_p -= (*new_msg)->msg - p->msg;
		output_len += 32;
		*new_msg = p;
	}
	iconv_close(cd);
	(*new_msg)->msg_length = output_p - (*new_msg)->msg;
	(*new_msg)->msg_type = SSHOUT_MSG_PLAIN;
	memcpy((*new_msg)->msg_to, msg->msg_to, sizeof (*new_msg)->msg_to);
	len = strnlen(sender_name ? : msg->msg_from, sizeof (*new_msg)->msg_from - 1);
	memcpy((*new_msg)->msg_from, sender_name ? : msg->msg_from, len);
	//if(len < sizeof (*new_msg)->msg_from) (*new_msg)->msg_from[len] = 0;
	(*new_msg)->msg_from[len] = 0;
	return 0;
}
#endif

static int dispatch_message(int sender_fd, const struct local_message *msg, const fd_set *client_fds, int fd_max_size) {
	const char *sender_name = user_names[sender_fd];
#ifdef HAVE_ICONV
	const char *from_encoding = user_text_encodings[sender_fd];
#endif
	int is_broadcast = strcmp(msg->msg_to, GLOBAL_NAME) == 0 || strcmp(msg->msg_to, "*") == 0;
	size_t packet_len = sizeof(struct local_packet) + sizeof(struct local_message) + msg->msg_length;
	struct local_packet *packet = malloc(packet_len);
	if(!packet) {
		syslog(LOG_ERR, "dispatch_message: out of memory");
		return -1;
	}
	packet->length = packet_len - sizeof packet->length;
	packet->type = SSHOUT_LOCAL_DISPATCH_MESSAGE;
	struct local_message *payload_p = (struct local_message *)packet->data;
	memcpy(payload_p, msg, sizeof(struct local_message) + msg->msg_length);
	size_t sender_name_len = strnlen(sender_name, USER_NAME_MAX_LENGTH - 1);
	memcpy(payload_p->msg_from, sender_name, sender_name_len);
	payload_p->msg_from[sender_name_len] = 0;
	int r = 0;
	int fd = 0;
	int found = 0;
	do {
		if(!FD_ISSET(fd, client_fds)) continue;
		if(!*user_names[fd]) continue;
		if(!is_broadcast && strcmp(user_names[fd], msg->msg_to)) {
			// Not the target user, but we also need to send the message back to sender
			if(strcmp(user_names[fd], sender_name)) continue;
		} else found = 1;
		struct local_packet *cur_packet = packet;
		size_t cur_packet_len = packet_len;
#ifdef HAVE_ICONV
		if(fd != sender_fd && from_encoding && msg->msg_type == SSHOUT_MSG_PLAIN) {
			const char *to_encoding = user_text_encodings[fd];
			if(to_encoding && strcmp(from_encoding, to_encoding)) {
				struct local_message *new_msg;
				if(convert_message(from_encoding, to_encoding, sender_name, msg, &new_msg) < 0) {
					syslog_perror("dispatch_message: failed to convert text encoding from %s to %s",
						from_encoding, to_encoding);
				} else {
					cur_packet_len = sizeof(struct local_packet) + sizeof(struct local_message) + new_msg->msg_length;
					cur_packet = malloc(cur_packet_len);
					if(!cur_packet) {
						syslog(LOG_ERR, "dispatch_message: out of memory when converting character set");
						free(new_msg);
						continue;
					}
					cur_packet->length = cur_packet_len - sizeof cur_packet->length;
					cur_packet->type = SSHOUT_LOCAL_DISPATCH_MESSAGE;
					memcpy(cur_packet->data, new_msg, sizeof(struct local_message) + new_msg->msg_length);
					free(new_msg);
				}
			}
		}
#endif
		if(sync_write(fd, cur_packet, cur_packet_len) < 0) {
			syslog_perror("dispatch_message: from %d to %d: write",
				sender_fd, fd);
			r = -1;
		}
#ifdef HAVE_ICONV
		if(cur_packet != packet) free(cur_packet);
#endif
	} while(++fd < fd_max_size);
	free(packet);
	if(!found) {
		size_t name_len = strnlen(msg->msg_to, USER_NAME_MAX_LENGTH - 1);
		packet_len = sizeof(struct local_packet) + name_len + 1;
		packet = malloc(packet_len);
		if(!packet) {
			syslog(LOG_ERR, "dispatch_message: out of memory");
			return -1;
		}
		packet->length = packet_len - sizeof packet->length;
		packet->type = SSHOUT_LOCAL_USER_NOT_FOUND;
		memcpy(packet->data, msg->msg_to, name_len);
		packet->data[name_len] = 0;
		while(write(sender_fd, packet, packet_len) < 0) {
			if(errno == EINTR) continue;
			syslog_perror("dispatch_message: write");
			r = -1;
			break;
		}
	}
	return r;
}

int server_mode(const struct sockaddr_un *socket_addr) {
	static const struct timeval timeout = { .tv_sec = 2 };

	FILE *pid_file = fopen("sshoutd.pid", "r");
	if(pid_file) {
		char buffer[16];
		if(fgetline(pid_file, buffer, sizeof buffer) > 0) {
			int pid = atoi(buffer);
			if(pid > 0 && kill(pid, 0) == 0) {
				fprintf(stderr, "Another server process %d is running\n", pid);
				return 1;
			}
		}
		fclose(pid_file);
	}
	pid_file = fopen("sshoutd.pid", "w");
	if(!pid_file) {
		perror("sshoutd.pid");
		return 1;
	}
	if(fprintf(pid_file, "%d\n", (int)getpid()) < 0) {
		perror("fprintf");
		return 1;
	}
	if(fclose(pid_file) == EOF) {
		perror("fclose");
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);

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

	openlog("sshoutd", LOG_PID, LOG_DAEMON);

	fd_set fdset;
	FD_ZERO(&fdset);
	int max_fd = fd;

	struct private_buffer buffers[FD_SETSIZE];
	int i;
	for(i=0; i<FD_SETSIZE; i++) {
		buffers[i].buffer = NULL;
	}

	while(1) {
		int have_client_fd_closed = 0;
		fd_set rfdset = fdset;
		FD_SET(fd, &rfdset);
		int n = select(max_fd + 1, &rfdset, NULL, NULL, NULL);
		if(n < 0) {
			if(errno == EINTR) continue;
			syslog_perror("select");
			sleep(2);
			continue;
		}
		int cfd;
		if(FD_ISSET(fd, &rfdset)) {
			struct sockaddr_un client_addr;
			socklen_t addr_len = sizeof client_addr;
			do {
				cfd = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
			} while(cfd == -1 && errno == EINTR);
			if(cfd == -1) {
				syslog_perror("accept");
				if(errno == EMFILE && n < 2) sleep(1);
			} else if(cfd < FD_SETSIZE) {
				syslog(LOG_DEBUG, "client fd %d", cfd);
			        if(setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) syslog_perror("setsockopt");
			        if(setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) syslog_perror("setsockopt");
				FD_SET(cfd, &fdset);
				if(cfd > max_fd) max_fd = cfd;
			} else {
				syslog(LOG_WARNING, "cannot add fd %d to set, too many clients", cfd);
				close(cfd);
			}
			n--;
		}
		for(cfd=0; n && cfd<FD_SETSIZE; cfd++) {
			if(FD_ISSET(cfd, &rfdset)) {
				n--;
				struct local_packet *packet;
				switch(get_local_packet(cfd, &packet, buffers + cfd)) {
					case GET_PACKET_EOF:
						syslog(LOG_INFO, "client fd %d EOF", cfd);
						goto end_of_connection;
					case GET_PACKET_ERROR:
						syslog_perror("read");
						goto end_of_connection;
					case GET_PACKET_SHORT_READ:
						syslog(LOG_NOTICE, "client fd %d short read", cfd);
						goto end_of_connection;
					case GET_PACKET_TOO_LARGE:
						syslog(LOG_WARNING, "client fd %d packet too large (%u bytes)",
							cfd, (unsigned int)packet);
						goto end_of_connection;
					case GET_PACKET_OUT_OF_MEMORY:
						syslog(LOG_WARNING, "client fd %d out of memory (allocating %u bytes)",
							cfd, (unsigned int)packet);
						goto end_of_connection;
					case GET_PACKET_INCOMPLETE:
						//syslog(LOG_DEBUG, "client fd %d incomplete packet received, read %zu bytes, total %zu bytes; will continue later",
						//	cfd, buffers[cfd].read_length, buffers[cfd].total_length);
						continue;
					case 0:
						break;
					default:
						syslog(LOG_WARNING, "client fd %d unknown error", cfd);
						//abort();
						goto end_of_connection;
				}
				switch(packet->type) {
					case SSHOUT_LOCAL_LOGIN:
						user_online(cfd, packet->data, packet->data + USER_NAME_MAX_LENGTH,
#ifdef HAVE_ICONV
							packet->data + USER_NAME_MAX_LENGTH + HOST_NAME_MAX_LENGTH,
#endif
							&fdset, max_fd + 1);
						break;
					case SSHOUT_LOCAL_POST_MESSAGE:
						if(!*user_names[cfd]) {
							syslog(LOG_NOTICE, "client fd %d posting message without login", cfd);
							break;
						}
						dispatch_message(cfd, (struct local_message *)packet->data,
							&fdset, max_fd + 1);
						break;
					case SSHOUT_LOCAL_GET_ONLINE_USERS:
						if(send_online_users(cfd, max_fd + 1) < 0) {
						//	syslog(LOG_NOTICE, "client fd %d send_online_users failed, disconnecting", cfd);
						//	goto end_of_connection;
						}
						break;
					default:
						syslog(LOG_WARNING, "client fd %d unknown packet type %d",
							cfd, packet->type);
						break;
				}
				free(packet);
				continue;
end_of_connection:
				user_offline(cfd, &fdset, max_fd + 1);
				close(cfd);
				FD_CLR(cfd, &fdset);
				have_client_fd_closed = 1;
				free(buffers[cfd].buffer);
				buffers[cfd].buffer = NULL;
			}
		}
		if(have_client_fd_closed) {
			max_fd = fd;
			for(i=0; i<FD_SETSIZE; i++) if(FD_ISSET(i, &fdset) && i > max_fd) max_fd = i;
		}
	}
}
