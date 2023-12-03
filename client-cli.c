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

#include "common.h"
#include "client.h"
#include "syncrw.h"
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <fcntl.h>
#include "file-helpers.h"
#include <termios.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define PRINT_NEWLINE 1
#define PRINT_REDISPLAY_INPUT 2

#define SHOWHTML_OFF 0
#define SHOWHTML_COLOR 1
#define SHOWHTML_PLAIN 2
#define SHOWHTML_RAW 3

#define COLOR_OFF 0
#define COLOR_ON 1
#define COLOR_AUTO 2

#define CSI_SGR_RESET "\e[0m"
#define CSI_SGR_BRIGHT "\e[1m"
#define CSI_SGR_BRIGHT_GREEN "\e[1;32m"
#define CSI_SGR_BRIGHT_BLUE "\e[1;34m"

static const char *sshout_user_name;
static int use_readline;
static int client_log_only;
static FILE *preference_file;
static int option_alert = 0;
static int option_showhtml = SHOWHTML_OFF;
static int option_color = COLOR_AUTO;

static void print_with_time(time_t t, int flags, const char *format, ...) {
	va_list ap;
	struct tm tm;
	if(t == -1) t = time(NULL);
	localtime_r(&t, &tm);
	if(!client_log_only) {
		if(use_readline) {
			int end = rl_end;
			rl_end = 0;
			rl_redisplay();
			rl_end = end;
		}
		if(option_alert) putchar('\a');
		putchar('\r');
	}
	printf("[%.2d:%.2d:%.2d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	if(flags & PRINT_NEWLINE) {
		putchar('\n');
		if(use_readline && (flags & PRINT_REDISPLAY_INPUT)) {
			//rl_reset_line_state();
			rl_on_new_line();
			rl_redisplay();
		}
	}
}

static void print_filtered(const char *text) {
	int use_color = -1;
	while(*text) {
		switch(*text) {
			case '\r':
				if(!text[1] || text[1] == '\n') break;
			case '\x4':
			case '\x7':
			case '\x8':
			case '\x1b':
			case '\x7f':
				if(use_color == -1) use_color = (option_color == COLOR_AUTO && isatty(STDOUT_FILENO)) || option_color == COLOR_ON;
				if(use_color) fputs(CSI_SGR_BRIGHT, stdout);
				printf("\\x%.2hhx", *text);
				if(use_color) fputs(CSI_SGR_RESET, stdout);
				break;
			default:
				putchar(*text);
				break;
		}
		text++;
	}
	putchar('\n');
	if(use_readline) {
		rl_on_new_line();
		rl_redisplay();
	}
}

static void write_preference(const char *name, const char *value) {
	if(!preference_file) return;
	if(fseek(preference_file, 0, SEEK_SET) < 0) return;
	size_t name_len = strlen(name);
	size_t value_len = strlen(value);
	char name_equal[name_len + 2];
	memcpy(name_equal, name, name_len);
	name_equal[name_len] = '=';
	name_equal[name_len + 1] = 0;
	char buffer[256];
	while(1) {
		int len = fgetline(preference_file, buffer, sizeof buffer);
		if(len == -1) break;
		if(len == -2) continue;
		if(len == 0 || *buffer == '#') continue;
		if(strncmp(buffer, name_equal, name_len + 1) == 0) {
			if((size_t)len == name_len + 1 + value_len) {
				int n = fseek(preference_file, -1, SEEK_CUR) == 0 && fgetc(preference_file) == '\n';
				if(fseek(preference_file, -n - value_len, SEEK_CUR) < 0) return;
				fputs(value, preference_file);
				fflush(preference_file);
				return;
			} else {
				if(fbackwardoverwrite(preference_file, len + 1) < 0) return;
				if(fseek(preference_file, 0, SEEK_END) < 0) return;
				break;
			}
		}
	}
	if(fseek(preference_file, -1, SEEK_CUR) == 0) {
		int need_put_new_line = fgetc(preference_file) != '\n';
		fflush(preference_file);
		if(need_put_new_line) fputc('\n', preference_file);
	}
	fprintf(preference_file, "%s=%s\n", name, value);
	fflush(preference_file);
}

static void command_who(int fd, int argc, char **argv) {
	if(client_send_request_get_online_users(fd) < 0) {
		perror("who: write");
	}
}

static void command_alert(int fd, int argc, char **argv) {
	if(argc != 2) {
usage:
		fprintf(stderr, _("Usage: %s off|on\n"), argv[0]);
		return;
	}
	if(strcmp(argv[1], "off") == 0) option_alert = 0;
	else if(strcmp(argv[1], "on") == 0) option_alert = 1;
	else goto usage;
	write_preference("alert", option_alert ? "1" : "0");
}

static void command_showhtml(int fd, int argc, char **argv) {
	if(argc != 2) {
usage:
		fprintf(stderr, _("Usage: %s off|color|plain|raw\n"), argv[0]);
		return;
	}
	if(strcmp(argv[1], "off") == 0) option_showhtml = SHOWHTML_OFF;
	else if(strcmp(argv[1], "color") == 0) option_showhtml = SHOWHTML_COLOR;
	else if(strcmp(argv[1], "plain") == 0) option_showhtml = SHOWHTML_PLAIN;
	else if(strcmp(argv[1], "raw") == 0) option_showhtml = SHOWHTML_RAW;
	else goto usage;
	char buffer[2] = { '0' + option_showhtml, 0 };
	write_preference("showhtml", buffer);
}

static void command_color(int fd, int argc, char **argv) {
	if(argc != 2) {
usage:
		fprintf(stderr, _("Usage: %s off|on|auto\n"), argv[0]);
		return;
	}
	if(strcmp(argv[1], "off") == 0) option_color = COLOR_OFF;
	else if(strcmp(argv[1], "on") == 0) option_color = COLOR_ON;
	else if(strcmp(argv[1], "auto") == 0) option_color = COLOR_AUTO;
	else goto usage;
	char buffer[2] = { '0' + option_color, 0 };
	write_preference("color", buffer);
}

static void command_msg(int fd, int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, _("Usage: %s <user> <message> [<message> ...]\n"), argv[0]);
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
			if(!missing_ok) print_with_time(-1, PRINT_NEWLINE, _("No MOTD available"));
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
	print_with_time(-1, PRINT_NEWLINE, _("Message of the day:"));
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

static void command_pasteimage(int fd, int argc, char **argv) {
	if(argc < 2) {
		fprintf(stderr, _("Usage: %s <user>\n"), argv[0]);
		return;
	}
	int pipe_fds[2];
	if(pipe(pipe_fds) < 0) {
		perror("pipe");
		return;
	}
	pid_t pid = fork();
	if(pid == -1) {
		perror("fork");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return;
	}
	if(pid) {
		int status;
		close(pipe_fds[1]);
		struct local_message *buffer = NULL;
		//size_t local_msg_len = sizeof(struct local_message);
		size_t local_msg_len;
		size_t data_len = 0;
		int s;
		do {
			//local_msg_len += 256 * 1024;
			local_msg_len = sizeof(struct local_message) + data_len + 256 * 1024;
			if(local_msg_len > 1024 * 1024) {
				fputs(_("Image too large\n"), stderr);
				kill(pid, SIGKILL);
				break;
			}
			struct local_message *new_buffer = realloc(buffer, local_msg_len);
			if(!new_buffer) {
				fputs(_("Failed to receive image, out of memory\n"), stderr);
				kill(pid, SIGKILL);
				break;
			}
			buffer = new_buffer;
			s = sync_read(pipe_fds[0], buffer->msg + data_len, 256 * 1024);
			if(s < 0) {
				perror("read");
				kill(pid, SIGKILL);
				break;
			}
		} while(s && (data_len += s));
		close(pipe_fds[0]);
		while(waitpid(pid, &status, 0) < 0) {
			if(errno == EINTR) continue;
			perror("waitpid");
			free(buffer);
			return;
		}
		if(WIFSIGNALED(status)) {
			fprintf(stderr, _("child process terminated by signal %d\n"), WTERMSIG(status));
		}
		if(status == 0) {
			size_t receiver_len = strlen(argv[1]);
			if(receiver_len > USER_NAME_MAX_LENGTH - 1) receiver_len = USER_NAME_MAX_LENGTH - 1;
			memcpy(buffer->msg_to, argv[1], receiver_len);
			buffer->msg_to[receiver_len] = 0;
			buffer->msg_type = SSHOUT_MSG_IMAGE;
			buffer->msg_length = data_len;
			client_post_message(fd, buffer);
		}
		free(buffer);
	} else {
		close(pipe_fds[0]);
		close(1);
		if(dup2(pipe_fds[1], 1) == -1) {
			perror("dup2");
			_exit(1);
		}
		execlp("xclip", "xclip", "-o", "-selection", "clipboard", "-target", "image/jpeg", "-verbose", NULL);
		perror("xclip");
		_exit(127);
	}
}

static void command_listoptions(int fd, int argc, char **argv) {
	if(argc > 1 && strcmp(argv[1], "-e") == 0) {
		fputs("/alert ", stdout);
		puts(option_alert ? "on" : "off");
		fputs("/showhtml ", stdout);
		switch(option_showhtml) {
			case SHOWHTML_OFF:
				puts("off");
				break;
			case SHOWHTML_COLOR:
				puts("color");
				break;
			case SHOWHTML_PLAIN:
				puts("plain");
				break;
			case SHOWHTML_RAW:
				puts("raw");
				break;
		}
		fputs("/color ", stdout);
		switch(option_color) {
			case COLOR_OFF:
				puts("off");
				break;
			case COLOR_ON:
				puts("on");
				break;
			case COLOR_AUTO:
				puts("auto");
				break;
		}
	} else {
		/// To transtators: try not to change the string width
		fputs(_("Message alert:          "), stdout);
		puts(option_alert ? _("on") : _("off"));
		/// To transtators: try not to change the string width
		fputs(_("Showing HTML message:   "), stdout);
		switch(option_showhtml) {
			case SHOWHTML_OFF:
				puts(_("off"));
				break;
			case SHOWHTML_COLOR:
				puts(_("colorized text"));
				break;
			case SHOWHTML_PLAIN:
				puts(_("plain text"));
				break;
			case SHOWHTML_RAW:
				puts(_("raw html document"));
				break;
		}
		/// To transtators: try not to change the string width
		fputs(_("Use colorized output:   "), stdout);
		switch(option_color) {
			case COLOR_OFF:
				puts(_("off"));
				break;
			case COLOR_ON:
				puts(_("on"));
				break;
			case COLOR_AUTO:
				puts(_("automatic (if terminal)"));
				break;
		}
	}
}

static void command_version(int fd, int argc, char **argv) {
	puts(SSHOUT_VERSION_STRING);
	puts(_("Command line interface frontend"));
	puts(SSHOUT_COPYRIGHT_LINE);
	puts(SSHOUT_LICENSE_INFORMATION);
	printf("%s%s\n", _("Project page: "), "https://sourceforge.net/projects/sshout/");
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
	{ "alert", "off|on", command_alert },
	{ "bell", "off|on", command_alert },
	{ "showhtml", "off|color|plain|raw", command_showhtml },
	{ "color", "off|on|auto", command_color },
	{ "msg", "<user> <message> [<message> ...]", command_msg },
	{ "tell", "<user> <message> [<message> ...]", command_msg },
	{ "motd", "", command_motd },
	{ "pasteimage", "<user>", command_pasteimage },
	{ "listoptions", "[-e]", command_listoptions },
	{ "version", "", command_version },
	{ "quit", "", command_quit },
	{ "help", "", command_help },
	{ NULL, NULL, NULL }
};

static void command_help(int fd, int argc, char **argv) {
	struct command *c = command_list;
	puts(_("Supported commands:"));
	while(c->name) {
		printf("/%s %s\n", c->name, c->usage);
		c++;
	}
	puts(_("End of list\n"));
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
	if(!*command) return;
	char **argv = malloc(sizeof(char *));
	char *buffer;
	if(!argv || !(buffer = strdup(command))) {
#ifndef NO_NLS
		print_with_time(-1, PRINT_NEWLINE, "do_command: out of memory");
#else
		print_with_time(-1, PRINT_NEWLINE, "do_command: %s", _("Out of memory"));
#endif
		free(argv);
		return;
	}
	int argc = parse_tokens(buffer, &argv, 0);
	if(argc < 1) {
		if(argc < 0) {
#ifndef NO_NLS
			print_with_time(-1, PRINT_NEWLINE, "do_command: out of memory");
#else
			print_with_time(-1, PRINT_NEWLINE, "do_command: %s", _("Out of memory"));
#endif
		}
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
	print_with_time(-1, PRINT_NEWLINE, _("Error: Unknown command '%s'"), argv[0]);
	free(argv);
	free(buffer);
}

static void print_online_users(const struct local_online_users_info *info) {
	int i = 0;
	while(i < info->count) {
		const struct local_online_user *u = info->user + i++;
		printf("%c %3d %-16s	%s\n", u->id == info->your_id ? '*' : ' ',
			u->id, u->user_name, u->host_name);
	}
}

static void print_message(const struct local_message *msg) {
	const char *color_begin_from;
	const char *color_begin_to;
	const char *color_end;
	char *text = NULL;
	int need_parse_html = 0;
	if((option_color == COLOR_AUTO && isatty(STDOUT_FILENO)) || option_color == COLOR_ON) {
		color_begin_from = strcmp(msg->msg_from, sshout_user_name) == 0 ? CSI_SGR_BRIGHT_GREEN : CSI_SGR_BRIGHT_BLUE;
		color_begin_to = strcmp(msg->msg_to, sshout_user_name) == 0 ? CSI_SGR_BRIGHT_GREEN : CSI_SGR_BRIGHT_BLUE;
		color_end = CSI_SGR_RESET;
	} else {
		color_begin_from = "";
		color_begin_to = "";
		color_end = "";
	}
	switch(msg->msg_type) {
		case SSHOUT_MSG_RICH:
			switch(option_showhtml) {
				case SHOWHTML_OFF:
					text = strdup("[HTML]");
					if(!text) {
						print_with_time(-1, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT,
							_("Out of memory"));
						return;
					}
					break;
				case SHOWHTML_COLOR:
					need_parse_html = 1;
					break;
				case SHOWHTML_PLAIN:
					need_parse_html = 1;
					break;
				case SHOWHTML_RAW:
					break;
			}
			break;
		case SSHOUT_MSG_IMAGE:
			text = strdup(_("[Image]"));
			if(!text) {
				print_with_time(-1, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT, _("Out of memory"));
				return;
			}
			break;
	}
	if(!need_parse_html && !text) {
		text = malloc(msg->msg_length + 1);
		if(!text) {
			print_with_time(-1, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT, _("Out of memory"));
			return;
		}
		memcpy(text, msg->msg, msg->msg_length);
		text[msg->msg_length] = 0;
	}
	if(strcmp(msg->msg_to, GLOBAL_NAME) == 0 || strcmp(msg->msg_to, "*") == 0) {
		print_with_time(-1, 0, "%s%s%s: ", color_begin_from, msg->msg_from, color_end);
	} else {
		print_with_time(-1, 0, "%s%s%s to %s%s%s: ",
			color_begin_from, msg->msg_from, color_end,
			color_begin_to, msg->msg_to, color_end);
	}
	if(need_parse_html) {
		putchar('\n');
		int pipe_fds[2];
		if(pipe(pipe_fds) < 0) {
			perror("pipe");
			return;
		}
		pid_t pid = fork();
		if(pid == -1) {
			perror("fork");
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			return;
		}
		if(pid) {
			int status;
			close(pipe_fds[0]);
			if(sync_write(pipe_fds[1], msg->msg, msg->msg_length) < 0) {
				perror("write");
			}
			close(pipe_fds[1]);
			while(waitpid(pid, &status, 0) < 0) {
				if(errno == EINTR) continue;
				perror("waitpid");
				return;
			}
			if(option_showhtml == SHOWHTML_COLOR) {
				fputs("\e[0m", stdout);
				fflush(stdout);		// Make the cursor back normal immediately
			}
			if(WIFSIGNALED(status)) {
				fprintf(stderr, _("child process terminated by signal %d\n"), WTERMSIG(status));
			}
			if(use_readline) {
				rl_reset_line_state();
				rl_redisplay();
			}
		} else {
			close(pipe_fds[1]);
			close(0);
			if(dup2(pipe_fds[0], 0) == -1) {
				perror("dup2");
				_exit(1);
			}
			if(pipe_fds[0] != 0) close(pipe_fds[0]);
			execlp("elinks", "elinks", "-force-html", "-dump", "-dump-color-mode",
				option_showhtml == SHOWHTML_COLOR ? "1" : "0", "/dev/stdin", NULL);
			perror("elinks");
			_exit(1);
		}
	} else {
		print_filtered(text);
		free(text);
	}
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
		print_with_time(-1, PRINT_NEWLINE, _("Exiting ..."));
		if(use_readline) rl_callback_handler_remove();
		exit(0);
	}
	if(*line) {
		do_input_line(client_get_local_socket_fd(), line);
		HIST_ENTRY *last = history_get(history_length);
		if(!last || strcmp(last->line, line)) add_history(line);
	}
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
		if(date_str_len) print_with_time(t, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT, "[%s]", buffer);
		else print_with_time(t, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT, _("Error: cannot format current date"));
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
	if(use_readline) {
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
	}
	client_cli_do_tick();
}

static void open_preference(const char *user_name) {
	struct stat st;
	if(stat(SSHOUT_USERS_PREFERENCES_DIR, &st) < 0 && (errno != ENOENT || mkdir(SSHOUT_USERS_PREFERENCES_DIR, 0750) < 0)) {
		perror(SSHOUT_USERS_PREFERENCES_DIR);
		fputs(_("Cannot load or save perferences in this session\n"), stderr);
		return;
	}
	size_t user_name_len = strlen(user_name) + 1;
	char file_name[sizeof SSHOUT_USERS_PREFERENCES_DIR + user_name_len];
	memcpy(file_name, SSHOUT_USERS_PREFERENCES_DIR, sizeof SSHOUT_USERS_PREFERENCES_DIR - 1);
	file_name[sizeof SSHOUT_USERS_PREFERENCES_DIR - 1] = '/';
	memcpy(file_name + sizeof SSHOUT_USERS_PREFERENCES_DIR, user_name, user_name_len);
	int fd = open(file_name, O_RDWR | O_CREAT, 0640);
	if(fd == -1 || !(preference_file = fdopen(fd, "r+"))) {
		perror(file_name);
		fputs(_("Cannot load or save perferences in this session\n"), stderr);
		if(fd != -1) close(fd);
		return;
	}
	char buffer[256];
	while(1) {
		int len = fgetline(preference_file, buffer, sizeof buffer);
		if(len == -1) break;
		if(len == -2) continue;
		if(len == 0 || *buffer == '#') continue;
		if(strncmp(buffer, "alert=", 6) == 0) {
			if(len == 7) option_alert = buffer[6] == '1';
			else if(fbackwardoverwrite(preference_file, len + 1) < 0) break;
		} else if(strncmp(buffer, "showhtml=", 9) == 0) {
			if(len == 10) option_showhtml = buffer[9] - '0';
			else if(fbackwardoverwrite(preference_file, len + 1) < 0) break;
		} else if(strncmp(buffer, "color=", 6) == 0) {
			if(len == 7) option_color = buffer[6] - '0';
			else if(fbackwardoverwrite(preference_file, len + 1) < 0) break;
		} else {
			fprintf(stderr, _("Unrecognized option '%s', removing\n"), buffer);
			if(fbackwardoverwrite(preference_file, len + 1) < 0) break;
		}
	}
}

static void client_cli_init_io(const char *user_name) {
	if(client_log_only) {
		use_readline = 0;
	} else {
		char *always_use_readline = getenv("RL_FORCE_ENABLE");
		use_readline = (always_use_readline && *always_use_readline) || isatty(STDIN_FILENO);
	}
	if(use_readline) {
		rl_outstream = stderr;
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
		char *editing_mode = getenv("RL_EDITING_MODE");
		if(editing_mode) {
			if(strcmp(editing_mode, "emacs") == 0) rl_editing_mode = 1;
			else if(strcmp(editing_mode, "vi") == 0) rl_editing_mode = 0;
		}
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	sshout_user_name = user_name;
	open_preference(user_name);
	print_motd(1);
}

static void client_cli_do_local_packet(int fd) {
	static struct private_buffer buffer;
	struct local_packet *packet;
	switch(get_local_packet(fd, &packet, &buffer)) {
		case GET_PACKET_EOF:
			print_with_time(-1, PRINT_NEWLINE, _("Server closed connection"));
			close(fd);
			if(use_readline) rl_callback_handler_remove();
			exit(0);
		case GET_PACKET_ERROR:
			perror("read");
			close(fd);
			if(use_readline) rl_callback_handler_remove();
			exit(1);
		case GET_PACKET_SHORT_READ:
			print_with_time(-1, PRINT_NEWLINE, _("Packet short read"));
			close(fd);
			if(use_readline) rl_callback_handler_remove();
			exit(1);
		case GET_PACKET_TOO_LARGE:
			print_with_time(-1, PRINT_NEWLINE, _("Packet too large"));
			close(fd);
			if(use_readline) rl_callback_handler_remove();
			exit(1);
		case GET_PACKET_OUT_OF_MEMORY:
			print_with_time(-1, PRINT_NEWLINE, _("Out of memory"));
			close(fd);
			if(use_readline) rl_callback_handler_remove();
			exit(1);
		case GET_PACKET_INCOMPLETE:
			return;
		case 0:
			break;
		default:
			print_with_time(-1, PRINT_NEWLINE, _("Internal error"));
			if(use_readline) rl_callback_handler_remove();
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
			print_with_time(-1, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT,
				_("User %s is %s"), (char *)packet->data,
				packet->type == SSHOUT_LOCAL_USER_ONLINE ? _("online") : _("offline"));
			break;
		case SSHOUT_LOCAL_USER_NOT_FOUND:
			print_with_time(-1, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT,
				_("User %s not found"),  (char *)packet->data);
			break;
		default:
			print_with_time(-1, PRINT_NEWLINE | PRINT_REDISPLAY_INPUT,
				_("Unknown packet type %d"), packet->type);
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

static char input_buffer[2048];
static int ss;

// fd is for local packet
static void client_cli_do_stdin(int fd) {
	if(use_readline) {
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
				print_with_time(-1, PRINT_NEWLINE, _("Exiting ..."));
				exit(0);
			}
			char *bs = buffer;
			while((bs = mem2chr(bs, '\b', 0x7f, s - (bs - buffer)))) {
				ss--;
				bs++;
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
				print_with_time(-1, PRINT_NEWLINE, _("Exiting ..."));
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
