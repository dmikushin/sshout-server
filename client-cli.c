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
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <fcntl.h>
#include <stdio.h>
#include <termios.h>
#include <time.h>
#include <errno.h>

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

static void command_who(int fd, int argc, char **argv) {
	if(client_send_request_get_online_users(fd) < 0) {
		perror("who: write");
	}
}

static struct command {
	const char *name;
	const char *usage;
	void (*func)(int, int, char **);
} command_list[] = {
	{ "who", "", command_who },
	{ "list", "", command_who },
	{ NULL, NULL, NULL }
};


static int parse_tokens(char *string, char ***tokens, int length) {
	/* Extract whitespace- and quotes- delimited tokens from the given string
	   and put them into the tokens array. Returns number of tokens
	   extracted. Length specifies the current size of tokens[].
	   THIS METHOD MODIFIES string.  */

	const char * whitespace = " \t\r\n";
	char * tokenEnd;
	const char * quoteCharacters = "\"\'";
	char * end = string + strlen(string);

	if(!string) return length;

	while(1) {
		const char *q;
		/* Skip over initial whitespace.  */
		string += strspn(string, whitespace);
		if(!*string) break;

		for(q = quoteCharacters; *q; ++q) {
			if(*string == *q) break;
		}
		if(*q) {
			/* Token is quoted.  */
			char quote = *string++;
			tokenEnd = strchr(string, quote);
			/* If there is no endquote, the token is the rest of the string.  */
			if(!tokenEnd) tokenEnd = end;
		} else {
			tokenEnd = string + strcspn(string, whitespace);
		}

		*tokenEnd = '\0';

		{
			char **new_tokens;
			int newlen = length + 1;
			new_tokens = realloc(*tokens, (newlen + 1) * sizeof (char *));
			if(!new_tokens) {
				/* Out of memory.  */
				return -1;
			}

			*tokens = new_tokens;
			(*tokens)[length] = string;
			length = newlen;
		}
		if(tokenEnd == end) break;
		string = tokenEnd + 1;
	}

	return length;
}

static void do_command(int fd, const char *command) {
	//size_t len = strlen(commnd) + 1;
	if(!*command) return;
	char **argv = malloc(sizeof(char *));
	char *buffer;
	if(!argv || !(buffer = strdup(command))) {
		print_with_time(-1, "do_command: out of memory");
		free(argv);
		return;
	}
	int argc = parse_tokens(buffer, &argv, 0);
	if(argc < 0) {
		print_with_time(-1, "do_command: out of memory");
		free(argv);
		free(buffer);
		return;
	}

	struct command *c = command_list;
	while(c->name) {
		if(strcmp(c->name, argv[0]) == 0) {
			c->func(fd, argc, argv);
			free(argv);
			free(buffer);
			return;
		}
		c++;
	}
	print_with_time(-1, "Error: Unknown command '%s'", argv[0]);
	free(argv);
	free(buffer);
}

static void print_online_users(const struct local_online_users_info *info) {
	int i = 0;
	print_with_time(-1, "your_id = %d", info->your_id);
	print_with_time(-1, "count = %d", info->count);
	while(i < info->count) {
		const struct local_online_user *u = info->user + i++;
		printf("%d	%s	%s	%s\n",
			u->id, u->user_name, u->host_name, u->id == info->your_id ? "*" : "");
	}
}

static void print_message(const struct local_message *msg) {
	if(msg->msg_type != SSHOUT_MSG_PLAIN) {
		print_with_time(-1, "%s: [Unsupported]", msg->msg_from);
		return;
	}
	char text[msg->msg_length + 1];
	memcpy(text, msg->msg, msg->msg_length);
	text[msg->msg_length] = 0;
	print_with_time(-1, "%s: %s", msg->msg_from, text);
}

static char **command_completion(const char *text, int start, int end) {
	static char *command_names[] = { "/help", NULL };
	print_with_time(-1, "function: command_completion(%p<%s>, %d, %d)\n", text, text, start, end);
	if(end < 1 || *text != '/') {
		rl_bind_key('	', rl_abort);
		return NULL;
	}
	return command_names;
}

static void do_input_line(int, const char *);

static void do_input_line_from_readline(char *line) {
	if(!line) {
		print_with_time(-1, "Exiting ...");
		if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
		exit(0);
	}
	if(!*line) return;
	do_input_line(client_get_local_socket_fd(), line);
	HIST_ENTRY *last = history_get(history_length);
	if(!last || strcmp(last->line, line)) add_history(line);
	free(line);
}

void client_cli_init_io() {
	if(isatty(STDIN_FILENO)) {
		rl_callback_handler_install(NULL, do_input_line_from_readline);
		rl_attempted_completion_function = command_completion;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
}

void client_cli_do_local_packet(int fd) {
	struct local_packet *packet;
	switch(get_local_packet(fd, &packet)) {
		case GET_PACKET_EOF:
			print_with_time(-1, "Server closed connection");
			close(fd);
			if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
			exit(0);
		case GET_PACKET_ERROR:
			perror("read");
			close(fd);
			if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
			exit(1);
		case GET_PACKET_SHORT_READ:
			print_with_time(-1, "Packet short read");
			close(fd);
			if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
			exit(1);
		case GET_PACKET_TOO_LARGE:
			print_with_time(-1, "Packet too large");
			close(fd);
			if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
			exit(1);
		case GET_PACKET_OUT_OF_MEMORY:
			print_with_time(-1, "Out of memory");
			close(fd);
			if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
			exit(1);
		case 0:
			break;
		default:
			print_with_time(-1, "Internal error");
			if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
			abort();
	}
	switch(packet->type) {
		case SSHOUT_LOCAL_STATUS:
			break;
		case SSHOUT_LOCAL_DISPATCH_MESSAGE:
			print_message((struct local_message *)packet->data);
			break;
		case SSHOUT_LOCAL_ONLINE_USERS_INFO:
			print_online_users((struct local_online_users_info *)packet->data);
			break;
		default:
			print_with_time(-1, "Unknown packet type %d", packet->type);
			break;
	}
	free(packet);
}

static void *mem2chr(const void *s, int c1, int c2, size_t n) {
	char *p = (void *)s;
	unsigned int i = 0;
	while(i < n) {
		if(p[i] == c1 || p[i] == c2) return p + i;
		i++;
	}
	return NULL;
}

static void *mem3chr(const void *s, int c1, int c2, int c3, size_t n) {
	char *p = (void *)s;
	unsigned int i = 0;
	while(i < n) {
		if(p[i] == c1 || p[i] == c2 || p[i] == c3) return p + i;
		i++;
	}
	return NULL;
}

static void do_input_line(int fd, const char *line) {
	if(*line == '/') {
		do_command(fd, line + 1);
	} else if(*line) {
		client_post_plain_text_message(fd, GLOBAL_NAME, line);
	}
}

static char input_buffer[4906];
static int ss;

// fd is for local packet
void client_cli_do_stdin(int fd) {
	if(isatty(STDIN_FILENO)) {
		rl_callback_read_char();
	} else {
		int s;
		if(ss == sizeof input_buffer) {
			char buffer[64];
			do {
				s = read(STDIN_FILENO, buffer, sizeof buffer);
			} while(s < 0 && errno == EINTR);
			if(s < 0) {
				if(errno == EAGAIN) return;
				perror("read");
				exit(1);
			}
			if(!s) {
				print_with_time(-1, "Exiting ...");
				exit(0);
			}
			char *bs = buffer;
			while((bs = mem2chr(bs, '\b', 0x7f, s - (bs - buffer)))) {
				ss--;
				//fputc('\b', stderr);
			}
		} else {
			do {
				s = read(STDIN_FILENO, input_buffer + ss, sizeof input_buffer - ss);
			} while(s < 0 && errno == EINTR);
			if(s < 0) {
				if(errno == EAGAIN) return;
				perror("read");
				exit(1);
			}
			if(!s) {
				print_with_time(-1, "Exiting ...");
				exit(0);
			}
			char *br = mem3chr(input_buffer + ss, 0, '\r', '\n', s);
			if(br) {
				int skip_len = 0;
				char *last_br;
				do {
					if(*br) *br = 0;
					br++;
					int line_len = br - input_buffer - skip_len;
					fputc('\r', stderr);
					do_input_line(fd, input_buffer + skip_len);
					last_br = br;
					br = mem3chr(br, 0, '\r', '\n', s - (br - (input_buffer + ss)));
					skip_len += line_len;
				} while(br);
				ss += s - skip_len;
				memmove(input_buffer, last_br, ss);
				//write(STDERR_FILENO, input_buffer, ss);
			} else {
				//write(STDERR_FILENO, input_buffer + ss, s);
				ss += s;
			}
		}
	}
}
