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
#include <termios.h>

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

static struct termios old;

static void set_terminal() {
	tcgetattr(STDIN_FILENO, &old);
	struct termios new = old;
	new.c_iflag &= ~ICRNL;		// Translate carriage return to newline on input
	new.c_lflag &= ~ICANON;		// Disable buffered i/o
	new.c_lflag &= ~ECHO;		// Disable echo
	tcsetattr(STDIN_FILENO, TCSANOW, &new);
}

static void reset_terminal() {
	tcsetattr(STDIN_FILENO, TCSANOW, &old);
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

void client_cli_init_stdin() {
	if(isatty(STDIN_FILENO)) set_terminal();
	else setvbuf(stdout, NULL, _IOLBF, 0);
	rl_attempted_completion_function = command_completion;
}

void client_cli_do_local_packet(int fd) {
	struct local_packet *packet;
	switch(get_local_packet(fd, &packet)) {
		case GET_PACKET_EOF:
			print_with_time(-1, "Server closed connection");
			close(fd);
			if(isatty(STDIN_FILENO)) reset_terminal();
			exit(0);
		case GET_PACKET_ERROR:
			perror("read");
			close(fd);
			if(isatty(STDIN_FILENO)) reset_terminal();
			exit(1);
		case GET_PACKET_SHORT_READ:
			print_with_time(-1, "Packet short read");
			close(fd);
			if(isatty(STDIN_FILENO)) reset_terminal();
			exit(1);
		case GET_PACKET_TOO_LARGE:
			print_with_time(-1, "Packet too large");
			close(fd);
			if(isatty(STDIN_FILENO)) reset_terminal();
			exit(1);
		case GET_PACKET_OUT_OF_MEMORY:
			print_with_time(-1, "Out of memory");
			close(fd);
			if(isatty(STDIN_FILENO)) reset_terminal();
			exit(1);
		case 0:
			break;
		default:
			print_with_time(-1, "Internal error");
			if(isatty(STDIN_FILENO)) reset_terminal();
			abort();
	}
	switch(packet->type) {
		case SSHOUT_LOCAL_STATUS:
			break;
		case SSHOUT_LOCAL_DISPATCH_MESSAGE:
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

// fd is for local packet
void client_cli_do_stdin(int fd) {
	char *line = readline(NULL);
	//char *line = readline("SSHOUT");
	if(!line) {
		print_with_time(-1, "Exiting ...");
		if(isatty(STDIN_FILENO)) reset_terminal();
		exit(0);
	}
	if(*line == '/') {
		print_with_time(-1, "command ...");
		do_command(fd, line + 1);
	} else if(*line) {
		print_with_time(-1, "send msg '%s' ...", line);
	}
	free(line);
}
