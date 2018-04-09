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

static void do_command(int fd, const char *command) {
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
	} else {
		print_with_time(-1, "send msg '%s' ...", line);
	}
	free(line);
}
