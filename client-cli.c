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
#include "syncrw.h"
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
#include <signal.h>
#include <locale.h>

static int client_log_only;
static int option_alarm = 0;

static void print_with_time(time_t t, const char *format, ...) {
	va_list ap;
	struct tm tm;
	if(t == -1) t = time(NULL);
	localtime_r(&t, &tm);
	if(option_alarm) putchar('\a');
	if(!client_log_only) putchar('\r');
	printf("[%.2d:%.2d:%.2d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
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

static void command_alarm(int fd, int argc, char **argv) {
	if(argc != 2) {
usage:
		fprintf(stderr, "Usage: %s off|on\n", argv[0]);
		return;
	}
	if(strcmp(argv[1], "off") == 0) option_alarm = 0;
	else if(strcmp(argv[1], "on") == 0) option_alarm = 1;
	else goto usage;
}

static void command_msg(int fd, int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, "Usage: %s <user> <message> [<message> ...]\n", argv[0]);
		return;
	}
	const char *user = argv[1];
	argv += 2;
	char *msg = NULL;
	size_t msg_len = 0, last_i;
	do {
		size_t a_len = strlen(*argv);
		last_i = msg_len;
		msg_len += a_len + 1;
		char *new_msg = realloc(msg, msg_len);
		if(!new_msg) {
			perror("realloc");
			free(msg);
			return;
		}
		msg = new_msg;
		memcpy(msg + last_i, *argv, a_len);
		msg[msg_len - 1] = ' ';
	} while(*++argv);
	msg[msg_len - 1] = 0;
	client_post_plain_text_message(fd, user, msg);
	free(msg);
}

static void print_motd(int missing_ok) {
	char buffer[1024];
	int fd = open(SSHOUT_MOTD_FILE, O_RDONLY);
	if(fd == -1) {
		if(errno == ENOENT) {
			if(!missing_ok) print_with_time(-1, "No MOTD available");
			return;
		}
		perror(SSHOUT_MOTD_FILE);
		return;
	}
	int s = sync_read(fd, buffer, sizeof buffer);
	if(s < 0) {
		perror("read: " SSHOUT_MOTD_FILE);
		return;
	}
	if(!s) return;
	int have_new_line = buffer[s - 1] == '\n';
	print_with_time(-1, "Message of the day:");
	s = sync_write(STDOUT_FILENO, buffer, s);
	if(s < 0) {
		perror("write: stdout");
		return;
	}
	if(!have_new_line) putchar('\n');
}

static void command_motd(int fd, int argc, char **argv) {
	print_motd(0);
}

static void command_quit(int fd, int argc, char **argv) {
	close(fd);
	exit(0);
}

static void command_help(int, int, char **);

static struct command {
	const char *name;
	const char *usage;
	void (*func)(int, int, char **);
} command_list[] = {
	{ "who", "", command_who },
	{ "list", "", command_who },
	{ "alarm", "off|on", command_alarm },
	{ "msg", "<user> <message> [<message> ...]", command_msg },
	{ "tell", "<user> <message> [<message> ...]", command_msg },
	{ "motd", "", command_motd },
	{ "quit", "", command_quit },
	{ "help", "", command_help },
	{ NULL, NULL, NULL }
};

static void command_help(int fd, int argc, char **argv) {
	struct command *c = command_list;
	puts("Supported commands:");
	while(c->name) {
		printf("/%s %s\n", c->name, c->usage);
		c++;
	}
	puts("End of list\n");
}

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
	argv[argc] = 0;

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
	//print_with_time(-1, "your_id = %d", info->your_id);
	//print_with_time(-1, "count = %d", info->count);
	while(i < info->count) {
		const struct local_online_user *u = info->user + i++;
		printf("%d	%s	%s	%s\n",
			u->id, u->user_name, u->host_name, u->id == info->your_id ? "*" : "");
	}
}

static void print_message(const struct local_message *msg) {
	char *text = NULL;
	switch(msg->msg_type) {
		case SSHOUT_MSG_RICH:
			text = strdup("[HTML]");
			break;
		case SSHOUT_MSG_IMAGE:
			text = strdup("[Image]");
			break;
	}
	if(!text) {
		text = malloc(msg->msg_length + 1);
		if(!text) {
			print_with_time(-1, "Out of memory");
			return;
		}
		memcpy(text, msg->msg, msg->msg_length);
		text[msg->msg_length] = 0;
	}
	if(strcmp(msg->msg_to, GLOBAL_NAME) == 0) {
		print_with_time(-1, "%s: %s", msg->msg_from, text);
	} else {
		print_with_time(-1, "%s to %s: %s", msg->msg_from, msg->msg_to, text);
	}
	free(text);
}

static char *command_generator(const char *text, int state) {
	static int len;
	static struct command *c;

	if(!state) {
		if(*text != '/') return NULL;
		len = strlen(text);
		c = command_list;
	}

	while(c->name) {
		if(strncmp(c->name, text + 1, len - 1) == 0) {
			size_t len = strlen(c->name) + 1;
			char *name = malloc(len + 1);
			if(!name) return NULL;
			*name = '/';
			memcpy(name + 1, c->name, len);
			c++;
			return name;
		}
		c++;
	}
	return NULL;
}

static char **command_completion(const char *text, int start, int end) {
	rl_attempted_completion_over = 1;
	if(start > 0 || *text != '/') return NULL;
	return rl_completion_matches(text, command_generator);
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

static int last_day = -1;

static void client_cli_do_tick() {
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	if(last_day == -1) last_day = tm->tm_yday;
	else if(last_day != tm->tm_yday) {
		char buffer[512];
		size_t date_str_len = strftime(buffer, sizeof buffer, "%x", tm);
		if(date_str_len) print_with_time(t, "[%s]", buffer);
		else print_with_time(t, "Error: cannot format current date");
		last_day = tm->tm_yday;
	}
}

static int got_sigint = 0;
static int got_sigwinch = 0;

static void signal_handler(int sig) {
	switch(sig) {
		case SIGINT:
			got_sigint = 1;
			break;
		case SIGWINCH:
			got_sigwinch = 1;
			break;
		default:
			fprintf(stderr, "%s: unknown sig %d\n", __func__, sig);
			break;
	}
}

static void client_cli_do_after_signal() {
	if(!got_sigint) return;
	//rl_reset_line_state();
	rl_free_line_state();
	RL_UNSETSTATE(RL_STATE_ISEARCH|RL_STATE_NSEARCH|RL_STATE_VIMOTION|RL_STATE_NUMERICARG|RL_STATE_MULTIKEY);
	//rl_done = 1;
	rl_line_buffer[rl_point = rl_end = rl_mark = 0] = 0;
	rl_restore_prompt();
	//rl_echo_signal_char(sig);
	//fputc('\n', stderr);
	fputs("^C\n", stderr);
	rl_redisplay();
	got_sigint = 0;
	client_cli_do_tick();
}

static void client_cli_init_io(const char *user_name) {
	if(isatty(STDIN_FILENO)) {
		rl_callback_handler_install(NULL, do_input_line_from_readline);
		rl_attempted_completion_function = command_completion;
		//rl_persistent_signal_handlers = 1;
		/* We have to setup our own signals handler since 
		 * rl_persistent_signal_handlers is not available in Readline 6
		 */
		static struct sigaction act = { .sa_handler = signal_handler };
		sigaction(SIGINT, &act, NULL);
		sigaction(SIGWINCH, &act, NULL);
		rl_catch_signals = 0;
		rl_catch_sigwinch = 0;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	setlocale(LC_TIME, "");
	print_motd(1);
}

static void client_cli_do_local_packet(int fd) {
	static struct private_buffer buffer;
	struct local_packet *packet;
	switch(get_local_packet(fd, &packet, &buffer)) {
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
		case GET_PACKET_INCOMPLETE:
			return;
		case 0:
			break;
		default:
			print_with_time(-1, "Internal error");
			if(isatty(STDIN_FILENO)) rl_callback_handler_remove();
			abort();
	}
	switch(packet->type) {
		case SSHOUT_LOCAL_DISPATCH_MESSAGE:
			print_message((struct local_message *)packet->data);
			break;
		case SSHOUT_LOCAL_ONLINE_USERS_INFO:
			print_online_users((struct local_online_users_info *)packet->data);
			break;
		case SSHOUT_LOCAL_USER_ONLINE:
		case SSHOUT_LOCAL_USER_OFFLINE:
			print_with_time(-1, "User %s is %s", (char *)packet->data,
				packet->type == SSHOUT_LOCAL_USER_ONLINE ? "online" : "offline");
			break;
		case SSHOUT_LOCAL_USER_NOT_FOUND:
			print_with_time(-1, "User %s not found",  (char *)packet->data);
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
static void client_cli_do_stdin(int fd) {
	if(isatty(STDIN_FILENO)) {
		if(got_sigwinch) {
			rl_resize_terminal();
			got_sigwinch = 0;
		}
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

void client_cli_get_actions(struct client_frontend_actions *a, int log_only) {
	a->init_io = client_cli_init_io;
	a->do_local_packet = client_cli_do_local_packet;
	a->do_stdin = client_cli_do_stdin;
	a->do_after_signal = client_cli_do_after_signal;
	a->do_tick = client_cli_do_tick;
	client_log_only = log_only;
}
