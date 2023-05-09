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

static struct local_online_user online_users[FD_SETSIZE];
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

static void broadcast_user_state(const char *user_name, int on, const int *client_fds) {
	unsigned int i = 0;
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
	do {
		if(online_users[i].id == -1) continue;
		while(write(client_fds[online_users[i].id], packet, packet_len) < 0) {
			if(errno == EINTR) continue;
			syslog_perror("broadcast_user_state: to %d: write", online_users[i].id);
			break;
		}
	} while(++i < sizeof online_users / sizeof *online_users);
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

static int user_online(int id, const char *user_name, const char *host_name,
#ifdef HAVE_ICONV
  const char *text_encoding,
#endif
  int *index, const int *client_fds) {
	int found_dup = 0;
	unsigned int i = 0;
	while(online_users[i].id != -1) {
		if(!found_dup && strcmp(online_users[i].user_name, user_name) == 0) found_dup = 1;
		if(++i >= sizeof online_users / sizeof *online_users) {
			syslog(LOG_WARNING, "cannot let user '%s' from %s login: too many users", user_name, host_name);
			return -1;
		}
	}
	struct local_online_user *p = online_users + i;
	p->id = id;
	size_t len = strnlen(user_name, sizeof p->user_name - 1);
	memcpy(p->user_name, user_name, len);
	p->user_name[len] = 0;
	len = strnlen(host_name, sizeof p->host_name - 1);
	memcpy(p->host_name, host_name, len);
	p->host_name[len] = 0;
	*index = i;
#ifdef HAVE_ICONV
	if(*text_encoding) user_text_encodings[i] = strdup(text_encoding);
#endif
	while(!found_dup && ++i < sizeof online_users / sizeof *online_users) {
		if(online_users[i].id != -1 && strcmp(online_users[i].user_name, user_name) == 0) found_dup = 1;
	}
	syslog(LOG_INFO, "user %s login from %s id %d dup %d", user_name, host_name, id, found_dup);
#ifdef HAVE_UPDWTMPX
	if(access("wtmpx", W_OK) == 0) {
		struct timeval tv;
		if(gettimeofday(&tv, NULL) == 0) {
			pid_t pid = get_pid_from_unix_socket(client_fds[id]);
			struct utmpx utx = {
				.ut_type = USER_PROCESS,
				.ut_pid = pid == -1 ? id : pid,
				.ut_tv.tv_sec = tv.tv_sec,
				.ut_tv.tv_usec = tv.tv_usec
			};
			snprintf(utx.ut_line, sizeof utx.ut_line, "%d", id);
			strncpy(utx.ut_user, user_name, sizeof utx.ut_user);
			strncpy(utx.ut_host, host_name, sizeof utx.ut_host);
			updwtmpx("wtmpx", &utx);
		}
	}
#endif
	if(!found_dup) broadcast_user_state(user_name, 1, client_fds);
	return 0;
}

static void user_offline(int id, const int *client_fds) {
	int found_dup = 0;
	unsigned int i = 0;
	while(online_users[i].id != id) {
		if(++i >= sizeof online_users / sizeof *online_users) return;
	}
#ifdef HAVE_ICONV
	free(user_text_encodings[i]);
	user_text_encodings[i] = NULL;
#endif
	const char *user_name = online_users[i].user_name;
#ifdef HAVE_UPDWTMPX
	const char *host_name = online_users[i].host_name;
#endif
	online_users[i].id = -1;
	i = 0;
	while(i < sizeof online_users / sizeof *online_users) {
		if(online_users[i].id != -1 && strcmp(online_users[i].user_name, user_name) == 0) {
			found_dup = 1;
			break;
		}
		i++;
	}
	if(!found_dup) broadcast_user_state(user_name, 0, client_fds);
	syslog(LOG_INFO, "user %s logout id %d dup %d", user_name, id, found_dup);
#ifdef HAVE_UPDWTMPX
	if(access("wtmpx", W_OK) == 0) {
		struct timeval tv;
		if(gettimeofday(&tv, NULL) == 0) {
			pid_t pid = get_pid_from_unix_socket(client_fds[id]);
			struct utmpx utx = {
				.ut_type = DEAD_PROCESS,
				.ut_pid = pid == -1 ? id : pid,
				.ut_tv.tv_sec = tv.tv_sec,
				.ut_tv.tv_usec = tv.tv_usec
			};
			snprintf(utx.ut_line, sizeof utx.ut_line, "%d", id);
			strncpy(utx.ut_user, user_name, sizeof utx.ut_user);
			strncpy(utx.ut_host, host_name, sizeof utx.ut_host);
			updwtmpx("wtmpx", &utx);
		}
	}
#endif
}

static int send_online_users(int receiver_id, int receiver_fd) {
	int r = 0;
	unsigned int i = 0, count = 0;
	do {
		if(online_users[i].id != -1) count++;
	} while(++i < sizeof online_users / sizeof *online_users);
	size_t packet_length = sizeof(struct local_packet) + sizeof(struct local_online_users_info) + sizeof(struct local_online_user) * count;
	struct local_packet *packet = malloc(packet_length);
	if(!packet) {
		syslog(LOG_ERR, "send_online_users: out of memory");
		return 0;	// XXX
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
		memcpy(info->user + count, online_users + i, sizeof(struct local_online_user));
	}
	if(sync_write(receiver_fd, packet, packet_length) < 0) {
		syslog_perror("send_online_users: to %d: write", receiver_id);
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

static int dispatch_message(int sender_i, const struct local_message *msg, const int *client_fds) {
	const struct local_online_user *sender = online_users + sender_i;
#ifdef HAVE_ICONV
	const char *from_encoding = user_text_encodings[sender_i];
#endif
	int r = 0;
	int i = 0;
	int found = 0;
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
	size_t sender_name_len = strnlen(sender->user_name, USER_NAME_MAX_LENGTH - 1);
	memcpy(payload_p->msg_from, sender->user_name, sender_name_len);
	payload_p->msg_from[sender_name_len] = 0;
	do {
		if(online_users[i].id == -1) continue;
		if(!is_broadcast && strcmp(online_users[i].user_name, msg->msg_to)) {
			// Not the target user, but we also need to send the message back to sender
			if(strcmp(online_users[i].user_name, sender->user_name)) continue;
		} else found = 1;
		struct local_packet *cur_packet = packet;
		size_t cur_packet_len = packet_len;
#ifdef HAVE_ICONV
		if(i != sender_i && from_encoding && msg->msg_type == SSHOUT_MSG_PLAIN) {
			const char *to_encoding = user_text_encodings[i];
			if(to_encoding && strcmp(from_encoding, to_encoding)) {
				struct local_message *new_msg;
				if(convert_message(from_encoding, to_encoding, sender->user_name, msg, &new_msg) < 0) {
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
		if(sync_write(client_fds[online_users[i].id], cur_packet, cur_packet_len) < 0) {
			//syslog(LOG_WARNING, "i = %d, id = %d, fd = %d", i, online_users[i].id, client_fds[online_users[i].id]);
			syslog_perror("dispatch_message: from %d to %d: write",
				sender->id, online_users[i].id);
			r = -1;
		}
#ifdef HAVE_ICONV
		if(cur_packet != packet) free(cur_packet);
#endif
	} while(++i < (int)(sizeof online_users / sizeof *online_users));
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
		while(write(client_fds[sender->id], packet, packet_len) < 0) {
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
	FD_SET(fd, &fdset);
	int max_fd = fd;

	int client_fds[FD_SETSIZE];
	struct private_buffer buffers[FD_SETSIZE];
	int online_users_indexes[FD_SETSIZE];
	int i;
	for(i=0; i<FD_SETSIZE; i++) {
		client_fds[i] = -1;
		buffers[i].buffer = NULL;
		online_users[i].id = -1;
		online_users_indexes[i] = -1;
	}

	while(1) {
		int have_client_fd_closed = 0;
		fd_set rfdset = fdset;
		int n = select(max_fd + 1, &rfdset, NULL, NULL, NULL);
		if(n < 0) {
			if(errno == EINTR) continue;
			syslog_perror("select");
			sleep(2);
			continue;
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
				if(errno == EMFILE && n < 2) sleep(1);
			} else if(cfd < FD_SETSIZE) {
				syslog(LOG_DEBUG, "client fd %d", cfd);
			        if(setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) syslog_perror("setsockopt");
			        if(setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) syslog_perror("setsockopt");
				i = 0;
				while(1) {
					if(i >= FD_SETSIZE) {
						syslog(LOG_WARNING, "cannot add fd %d to set, too many clients", cfd);
						close(cfd);
						break;
					}
					if(client_fds[i] == -1) {
						client_fds[i] = cfd;
						FD_SET(cfd, &fdset);
						if(cfd > max_fd) max_fd = cfd;
						syslog(LOG_INFO, "client %d fd %d", i, cfd);
						break;
					}
					i++;
				}
			} else {
				syslog(LOG_WARNING, "cannot add fd %d to set, too many clients", cfd);
				close(cfd);
			}
			n--;
		}
		for(i=0; n && i<FD_SETSIZE; i++) {
			int cfd = client_fds[i];
			if(cfd == -1) continue;
			if(FD_ISSET(cfd, &rfdset)) {
				n--;
				struct local_packet *packet;
				switch(get_local_packet(cfd, &packet, buffers + i)) {
					case GET_PACKET_EOF:
						syslog(LOG_INFO, "client %d fd %d EOF", i, cfd);
						goto end_of_connection;
					case GET_PACKET_ERROR:
						syslog_perror("read");
						goto end_of_connection;
					case GET_PACKET_SHORT_READ:
						syslog(LOG_NOTICE, "client %d fd %d short read", i, cfd);
						goto end_of_connection;
					case GET_PACKET_TOO_LARGE:
						syslog(LOG_WARNING, "client %d fd %d packet too large (%u bytes)",
							i, cfd, (unsigned int)packet);
						goto end_of_connection;
					case GET_PACKET_OUT_OF_MEMORY:
						syslog(LOG_WARNING, "client %d fd %d out of memory (allocating %u bytes)",
							i, cfd, (unsigned int)packet);
						goto end_of_connection;
					case GET_PACKET_INCOMPLETE:
						//syslog(LOG_DEBUG, "client %d fd %d incomplete packet received, read %zu bytes, total %zu bytes; will continue later",
						//	i, cfd, buffers[i].read_length, buffers[i].total_length);
						continue;
					case 0:
						break;
					default:
						syslog(LOG_WARNING, "client %d fd %d unknown error", i, cfd);
						//abort();
						goto end_of_connection;
				}
				switch(packet->type) {
					case SSHOUT_LOCAL_LOGIN:
						user_online(i, packet->data, packet->data + USER_NAME_MAX_LENGTH,
#ifdef HAVE_ICONV
							packet->data + USER_NAME_MAX_LENGTH + HOST_NAME_MAX_LENGTH,
#endif
							online_users_indexes + i, client_fds);
						break;
					case SSHOUT_LOCAL_POST_MESSAGE:
						if(online_users_indexes[i] == -1) {
							syslog(LOG_NOTICE, "client %d fd %d posting message without login", i, cfd);
							break;
						}
						dispatch_message(online_users_indexes[i],
							(struct local_message *)packet->data, client_fds);
						break;
					case SSHOUT_LOCAL_GET_ONLINE_USERS:
						if(send_online_users(i, cfd) < 0) {
						//	syslog(LOG_NOTICE, "client %d fd %d send_online_users failed, disconnecting", i, cfd);
						//	goto end_of_connection;
						}
						break;
					default:
						syslog(LOG_WARNING, "client %d fd %d unknown packet type %d",
							i, cfd, packet->type);
						break;
				}
				free(packet);
				continue;
end_of_connection:
				user_offline(i, client_fds);
				close(cfd);
				FD_CLR(cfd, &fdset);
				have_client_fd_closed = 1;
				client_fds[i] = -1;
				free(buffers[i].buffer);
				buffers[i].buffer = NULL;
				online_users_indexes[i] = -1;
			}
		}
		if(have_client_fd_closed) {
			max_fd = fd;
			for(i=0; i<FD_SETSIZE; i++) if(client_fds[i] > max_fd) max_fd = client_fds[i];
		}
	}
}
