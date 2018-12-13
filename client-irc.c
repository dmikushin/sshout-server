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

#ifdef ENABLE_IRC_FRONTEND

#include "common.h"
#include "client.h"
#include "irc.h"
#include "syncrw.h"
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <locale.h>
#include <ctype.h>
#include <time.h>

#define SERVER_NAME "sshout.sourceforge.net"

static const char *sshout_user_name;
static int is_irc_nick_name_set;
static char irc_user_name[10];
static int is_irc_registered;
static char irc_channel_name[51];
//static int is_irc_joined;

static void send_irc_line(const char *line) {
	size_t len = strnlen(line, 510);
	if(sync_write(STDOUT_FILENO, line, len) < 0) {
		perror("write");
		exit(1);
	}
	if(sync_write(STDOUT_FILENO, "\r\n", 2) < 0) {
		perror("write");
		exit(1);
	}
}

#if 0
static void send_irc_line_format(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	fputs("\r\n", stdout);
}
#endif

static void send_irc_reply(const char *command, ...) {
	va_list ap;
	fputs(command, stdout);
	//if(isdigit(command[0]) && isdigit(command[1]) && isdigit(command[2]) && !command[3]) {
	if(is_irc_registered) {
		putchar(' ');
		fputs(sshout_user_name, stdout);
	}
	va_start(ap, command);
	int is_trailing = 0;
#if 1
	const char *arg, *last_arg = NULL;
#else
	const char *arg;
	char *last_arg = NULL;
#endif
	while((arg = va_arg(ap, const char *))) {
		if(last_arg) {
			putchar(' ');
			if(is_trailing) putchar(':');
			else if(strchr(last_arg, ' ')) {
				is_trailing = 1;
				putchar(':');
			}
			fputs(last_arg, stdout);
			//free(last_arg);
		}
#if 1
		last_arg = arg;
#else
		last_arg = strdup(arg);
		if(!last_arg) {
			syslog(LOG_ERR, "send_irc_reply: out of memory");
			return;
		}
#endif
		//syslog(LOG_DEBUG, "send_irc_reply: last_arg = %p<%s>", last_arg, last_arg);
	}
	va_end(ap);
	if(last_arg) {
		fputs(" :", stdout);
		fputs(last_arg, stdout);
		//free(last_arg);
	}
	fputs("\r\n", stdout);
}

static void send_irc_welcome() {
	send_irc_reply(IRC_RPL_WELCOME, "Welcome to SSHOUT IRC frontend", NULL);
}

static void send_irc_myinfo() {
	//send_irc_reply(IRC_RPL_MYINFO, "SSHOUT IRC frontend", SSHOUT_VERSION_STRING, "wr", "n", NULL);
	printf(IRC_RPL_MYINFO " %s " SSHOUT_VERSION_STRING " wr n\r\n", sshout_user_name);
}

static void do_registered() {
	is_irc_registered = 1;
	send_irc_welcome();
	send_irc_myinfo();
}

static void send_irc_motd() {
	char buffer[503];
	int fd = open(SSHOUT_MOTD_FILE, O_RDONLY);
	if(fd == -1) {
		int e = errno;
		if(e != ENOENT) syslog(LOG_WARNING, "irc_command_motd: " SSHOUT_MOTD_FILE ": %s", strerror(e));
		send_irc_reply(IRC_ERR_NOMOTD, strerror(e), NULL);
		errno = e;
		return;
	}
	int s = sync_read(fd, buffer, sizeof buffer);
	if(s < 0) {
		int e = errno;
		if(e != ENOENT) syslog(LOG_WARNING, "irc_command_motd: read: %s", strerror(e));
		send_irc_reply(IRC_ERR_NOMOTD, strerror(e), NULL);
		errno = e;
		return;
	}
	//if(!s) return -1;

	size_t user_name_len = strlen(sshout_user_name);
	//sync_write(STDOUT_FILENO, IRC_RPL_MOTDSTART " :- sshout Message of the day -\r\n", 36);
	sync_write(STDOUT_FILENO, IRC_RPL_MOTDSTART " ", 4);
	sync_write(STDOUT_FILENO, sshout_user_name, user_name_len);
	sync_write(STDOUT_FILENO, " :- sshout Message of the day -\r\n", 33);
	//sync_write(STDOUT_FILENO, IRC_RPL_MOTD " :- ", 7);
	sync_write(STDOUT_FILENO, IRC_RPL_MOTD " ", 4);
	sync_write(STDOUT_FILENO, sshout_user_name, user_name_len);
	sync_write(STDOUT_FILENO, " :- ", 4);
	sync_write(STDOUT_FILENO, buffer, s);
	sync_write(STDOUT_FILENO, "\r\n", 2);
	//sync_write(STDOUT_FILENO, IRC_RPL_ENDOFMOTD " :End of MOTD\r\n", 18);
	sync_write(STDOUT_FILENO, IRC_RPL_ENDOFMOTD " ", 4);
	sync_write(STDOUT_FILENO, sshout_user_name, user_name_len);
	sync_write(STDOUT_FILENO, " :End of MOTD\r\n", 15);
}

static void send_irc_message(const struct local_message *msg) {
	if(!is_irc_registered) return;
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
			syslog(LOG_ERR, "send_irc_message: out of memory");
			return;
		}
		memcpy(text, msg->msg, msg->msg_length);
		text[msg->msg_length] = 0;
	}
	printf(":%s PRIVMSG %s :%s\r\n", msg->msg_from,
		strcmp(msg->msg_to, GLOBAL_NAME) == 0 ? irc_channel_name : msg->msg_to, text);
}

static void send_irc_online_users(const struct local_online_users_info *info) {
	int i = 0;
	fputs(IRC_RPL_NAMREPLY " ", stdout);
	fputs(sshout_user_name, stdout);
	fputs(" = #sshout :", stdout);
	while(i < info->count) {
		const struct local_online_user *u = info->user + i++;
		fputs(u->user_name, stdout);
		putchar(' ');
	}
	fputs("\r\n", stdout);
	send_irc_reply(IRC_RPL_ENDOFNAMES, "#sshout", "End of NAMES", NULL);
}

static void send_irc_user_join(const char *user_name) {
	if(strcmp(user_name, sshout_user_name) == 0) return;
	printf(":%s JOIN :#sshout\r\n", user_name);
}

static void send_irc_user_quit(const char *user_name) {
	printf(":%s QUIT :Quit: %s\r\n", user_name, user_name);
}

/*static void irc_command_not_implemented(int fd, int argc, */struct fixed_length_string {
	size_t len;
	const char *p;
}/* *argv) {
}*/;

static void irc_command_nick(int fd, int argc, struct fixed_length_string *argv) {
	syslog(LOG_DEBUG, "function: irc_command_nick(%d, %d, %p)", fd, argc, argv);
	if(argc < 1) {
		send_irc_reply(IRC_ERR_NONICKNAMEGIVEN, "Missing nick name", NULL);
		return;
	}
	if(argv->len != strlen(sshout_user_name) || memcmp(argv->p, sshout_user_name, argv->len)) {
		send_irc_reply(IRC_ERR_RESTRICTED, "Nick name didn't match the registered one", NULL);
		return;
	}
	is_irc_nick_name_set = 1;
	if(*irc_user_name) do_registered();
}

static void irc_command_user(int fd, int argc, struct fixed_length_string *argv) {
	syslog(LOG_DEBUG, "function: irc_command_user(%d, %d, %p)", fd, argc, argv);
	if(argc < 4) {
		send_irc_reply(IRC_ERR_NEEDMOREPARAMS, "USER", "Not enough parameters", NULL);
		return;
	}

/*
	int i = 0;
	while(i <= argc) {
		syslog(LOG_DEBUG, "argv[%d].len = %zu", i, argv[i].len);
		if(argv[i].len) syslog(LOG_DEBUG, "argv[%d].p[0] = %hhu'%c'", i, argv[i].p[0], argv[i].p[0]);
		i++;
	}
*/
	if(is_irc_registered) {
		send_irc_reply(IRC_ERR_ALREADYREGISTRED, "You cannot register again", NULL);
		return;
	}
	size_t user_name_len = argv[0].len > 9 ? 9 : argv[0].len;
	memcpy(irc_user_name, argv[0].p, user_name_len);
	irc_user_name[user_name_len] = 0;
	//syslog(LOG_DEBUG, "argv[1].len = %zu", argv[1].len);
/*
	if(argv[1].len != 1) {
		send_irc_reply(IRC_ERR_UNKNOWNMODE, "?", "User mode takes only 1 numeric", NULL);
	} else if(argv[1].p[0] != '0') {
		char c[2] = { argv[1].p[0], 0 };
		send_irc_reply(IRC_ERR_UNKNOWNMODE, c, "User modes other than 0 are not supported", NULL);
	}
*/
	if(is_irc_nick_name_set) do_registered();
}

static void irc_command_oper(int fd, int argc, struct fixed_length_string *argv) {
	if(argc < 2) {
		send_irc_reply(IRC_ERR_NEEDMOREPARAMS, "OPER", "Not enough parameters", NULL);
		return;
	}
	send_irc_reply(IRC_ERR_NOOPERHOST, "operator is not supported", NULL);
}

static void irc_command_mode(int fd, int argc, struct fixed_length_string *argv) {
	if(argc < 1) {
		send_irc_reply(IRC_ERR_NEEDMOREPARAMS, "MODE", "Not enough parameters", NULL);
		return;
	}
	//if(is_irc_joined) return;
	if(*irc_channel_name) return;
	if(argc == 1) {
		send_irc_reply(IRC_RPL_UMODEIS, "+wr", NULL);
		return;
	}
	if(argv->len != strlen(sshout_user_name) || memcmp(argv->p, sshout_user_name, argv->len)) {
		send_irc_reply(IRC_ERR_USERSDONTMATCH, "You cannot change mode for other users", NULL);
		return;
	}
}

static void irc_command_quit(int fd, int argc, struct fixed_length_string *argv) {
	if(argc > 0 && *irc_channel_name) {
		char buffer[22 + 504 + 1] = "Leaving IRC frontend: ";
		size_t len = argv->len;
		if(len > 504) len = 504;
		memcpy(buffer + 22, argv->p, len);
		buffer[22 + len] = 0;
		client_post_plain_text_message(fd, GLOBAL_NAME, buffer);
	}
	close(fd);
	exit(0);
}

static void irc_command_join(int fd, int argc, struct fixed_length_string *argv) {
	if(argc < 1) {
		send_irc_reply(IRC_ERR_NEEDMOREPARAMS, "JOIN", "Not enough parameters", NULL);
		return;
	}
	if(argv->len == 1 && argv->p[0] == '0') {
		//is_irc_joined = 1;
		strcpy(irc_channel_name, "#sshout");
		return;
	}
	// &#+!
	if(argv->len < 2) {
		//send_irc_reply(IRC_ERR_BADCHANMASK,
		return;
	}
#if 0
	int i = strchr("&#+!", argv->p[0]) ? 1 : 0;
	if(argv->len != 6 || memcmp(argv->p + i, "sshout", argv->len - i)) {
#else
	if(argv->len != 7 || memcmp(argv->p, "#sshout", argv->len)) {
#endif
		char channel[argv->len + 1];
		memcpy(channel, argv->p, argv->len);
		channel[argv->len] = 0;
		send_irc_reply(IRC_ERR_NOSUCHCHANNEL, channel, "Only one channel #sshout is available", NULL);
		return;
	}
	//is_irc_joined = 1;
	strcpy(irc_channel_name, "#sshout");
	//send_irc_topic();
	client_send_request_get_online_users(fd);
}

static void irc_command_names(int fd, int argc, struct fixed_length_string *argv) {
	client_send_request_get_online_users(fd);
}

static void irc_command_list(int fd, int argc, struct fixed_length_string *argv) {
	if(argc > 1) return;
	if(argc == 1) {
#if 0
		int i = strchr("&#+!", argv->p[0]) ? 1 : 0;
		if(argv->len != 6 || memcmp(argv->p + i, "sshout", argv->len - i)) return;
#else
		if(argv->len != 7 || memcmp(argv->p, "#sshout", argv->len)) return;
#endif
	}
	send_irc_reply(IRC_RPL_LISTSTART, "Channel", "Users  Name", NULL);
	send_irc_reply(IRC_RPL_LIST, "#sshout", "?", "There is only one", NULL);
	send_irc_reply(IRC_RPL_LISTEND, "End of LIST", NULL);
}

static void irc_command_privmsg(int fd, int argc, struct fixed_length_string *argv) {
	if(argc < 1) {
		send_irc_reply(IRC_ERR_NORECIPIENT, "Missing recipient", NULL);
		return;
	}
	if(argc < 2) {
		send_irc_reply(IRC_ERR_NOTEXTTOSEND, "Missing message", NULL);
		return;
	}
	if(!is_irc_registered) {
		send_irc_reply(IRC_ERR_NOTREGISTERED, "PRIVMSG", "You have not registered", NULL);
		return;
	}
	struct local_message *message = malloc(sizeof(struct local_message) + argv[1].len);
	if(!message) {
		syslog(LOG_ERR, "irc_command_privmsg: out of memory");
		return;
	}
#if 0
	if(argv[0].len == 7 && memcmp(argv[0].p, "#sshout", 7) == 0) {
#else
	if(argv[0].len > 0 && strchr("&#+!", argv[0].p[0])) {
#endif
		strcpy(message->msg_to, GLOBAL_NAME);
	} else {
		size_t receiver_len = argv[0].len;
		if(receiver_len > USER_NAME_MAX_LENGTH - 1) receiver_len = USER_NAME_MAX_LENGTH - 1;
		memcpy(message->msg_to, argv[0].p, receiver_len);
		message->msg_to[receiver_len] = 0;
	}
	message->msg_type = SSHOUT_MSG_PLAIN;
	message->msg_length = argv[1].len;
	memcpy(message->msg, argv[1].p, argv[1].len);
	client_post_message(fd, message);
	free(message);
	return;
}

static void irc_command_motd(int fd, int argc, struct fixed_length_string *argv) {
	if(argc > 0) return;
	send_irc_motd();
}

static void irc_command_version(int fd, int argc, struct fixed_length_string *argv) {
	if(argc > 0) return;
	char buffer[506];
	snprintf(buffer, sizeof buffer, SSHOUT_VERSION_STRING "\n"
		"IRC frontend\n"
		"Copyright 2015-2018 Rivoreo\n"
		"This is free software; see the source for copying conditions.\n"
		"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n"
		"PARTICULAR PURPOSE.\n"
		"Project page: https://sourceforge.net/projects/sshout/");
	send_irc_reply(IRC_RPL_VERSION, buffer, NULL);
}

static void irc_command_time(int fd, int argc, struct fixed_length_string *argv) {
	if(argc > 0) return;
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char buffer[512];
	size_t date_str_len = strftime(buffer, sizeof buffer, "%x %T %Z", tm);
	if(date_str_len) send_irc_reply(IRC_RPL_TIME, SERVER_NAME, buffer, NULL);
	else send_irc_reply(IRC_ERR_UNKNOWNERROR, "Error: cannot format current date time");
}

static void irc_command_ping(int fd, int argc, struct fixed_length_string *argv) {
	if(argc > 1) return;
#if 0
	char from_host[argv->len + 1];
	memcpy(from_host, argv->p, argv->len);
	from_host[argv->len] = 0;
	send_irc_reply("PONG", from_host, NULL);
#else
	sync_write(STDOUT_FILENO, "PONG :", 6);
	sync_write(STDOUT_FILENO, argv->p, argv->len);
	sync_write(STDOUT_FILENO, "\r\n", 2);
#endif
}

static struct command {
	const char *name;
#if 0
	void (*do_command)(int, int, struct fixed_length_string {
		size_t len;
		const char *p;
	} *);
#else
	void (*do_command)(int, int, struct fixed_length_string *);
#endif
} irc_commands[] = {
	{ "PASS", NULL },
	{ "NICK", irc_command_nick },
	{ "USER", irc_command_user },
	{ "OPER", irc_command_oper },
	{ "MODE", irc_command_mode },
	{ "QUIT", irc_command_quit },
	{ "JOIN", irc_command_join },
	{ "PART", NULL },
	{ "TOPIC", NULL },
	{ "NAMES", irc_command_names },
	{ "LIST", irc_command_list },
	{ "PRIVMSG", irc_command_privmsg },
	{ "NOTICE", irc_command_privmsg },
	{ "MOTD", irc_command_motd },
	{ "VERSION", irc_command_version },
	{ "TIME", irc_command_time },
	{ "PING", irc_command_ping },
	{ "PONG", NULL },
	{ NULL, NULL }
};

static void parse_irc_arg(const char *line, size_t len, int *argc, struct fixed_length_string **argv) {
	const char *space = "BUG!", *colon = line;
	unsigned int i = 0;
	do {
		while(line[i] == ' ') i++;
		if(line[i] == ':') do {
			i++;
			colon = memchr(line + i, ':', len - i);
			if(colon && (colon == line + i + 1 || colon[-1] != ' ')) {
				//syslog(LOG_INFO, "parse_irc_arg: malformed IRC line");
				//return;
				//continue;
				colon = NULL;
			}
			size_t a_len = (colon ? (colon - 1 - line) : len) - i;
			(*argc)++;
			*argv = realloc(*argv, sizeof(struct fixed_length_string) * (*argc + 1));
			if(!*argv) {
				syslog(LOG_ERR, "parse_irc_arg: out of memory");
				exit(1);
			}
			(*argv)[*argc - 1].len = a_len;
			(*argv)[*argc - 1].p = line + i;
		} while(colon && (i = colon - line));
		else {
			space = memchr(line + i, ' ', len - i);
			size_t a_len = (space ? (space - line) : len) - i;
			(*argc)++;
			*argv = realloc(*argv, sizeof(struct fixed_length_string) * (*argc + 1));
			if(!*argv) {
				syslog(LOG_ERR, "parse_irc_arg: out of memory");
				exit(1);
			}
			(*argv)[*argc - 1].len = a_len;
			(*argv)[*argc - 1].p = line + i;
		}
	} while(colon && space && (i = space - line + 1));
	(*argv)[*argc].len = 0;
	(*argv)[*argc].p = NULL;
}

static void do_irc_line(int fd, const char *line, size_t len) {
	//fprintf(stderr, "function: do_irc_line(%d, %p, %zu)\n", fd, line, len);
	//syslog(LOG_DEBUG, "function: do_irc_line(%d, %p, %zu)", fd, line, len);
	if(!len) return;
	const char *prefix = NULL;
	size_t prefix_len;
	const char *space;
	if(*line == ':') {
		space = memchr(line + 1, ' ', len - 1);
		if(!space) return;
		prefix = line + 1;
		prefix_len = space - line - 1;
		space++;
		len -= space - line;
		line = space;
	}
	if(prefix && strncmp(prefix, sshout_user_name, prefix_len)) {
		// Invalid prefix
		syslog(LOG_INFO, "do_irc_line: invalid prefix from client");
		return;
	}
	int argc = 0;
	struct fixed_length_string *argv = malloc(sizeof(struct fixed_length_string));
	if(!argv) {
		syslog(LOG_ERR, "do_irc_line: out of memory");
		exit(1);
	}
	space = memchr(line, ' ', len);
	if(space && space + 1 == line + len) {
		space = NULL;
		len--;
	}
	size_t command_len = space ? space - line : len;
	if(space) parse_irc_arg(space + 1, len - command_len - 1, &argc, &argv);
	else memset(argv, 0, sizeof(struct fixed_length_string));
	struct command *c = irc_commands;
	while(c->name) {
		if(strlen(c->name) == command_len && strncasecmp(c->name, line, command_len) == 0) {
			if(c->do_command) c->do_command(fd, argc, argv);
			free(argv);
			return;
		}
		c++;
	}
	char buffer[command_len + 1];
	memcpy(buffer, line, command_len);
	buffer[command_len] = 0;
	syslog(LOG_INFO, "do_irc_line: %s: command not found", buffer);
}

static char *syslog_ident;

static void client_irc_init(const char *user_name) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	setlocale(LC_TIME, "");
	size_t len = 8 + USER_NAME_MAX_LENGTH + 4 + 1;
	syslog_ident = malloc(len);
	if(!syslog_ident) {
		perror("malloc");
		exit(1);
	}
	snprintf(syslog_ident, len, "sshoutd:%s:irc", user_name);
	openlog(syslog_ident, LOG_PID, LOG_DAEMON);
	sshout_user_name = user_name;
	syslog(LOG_INFO, "IRC server started");
}

static void client_irc_do_local_packet(int fd) {
	static struct private_buffer buffer;
	struct local_packet *packet;
	int e = get_local_packet(fd, &packet, &buffer);
	switch(e) {
		case GET_PACKET_EOF:
			close(fd);
			exit(0);
		case GET_PACKET_ERROR:
			send_irc_reply(IRC_ERR_UNKNOWNERROR, "Local packet read error", strerror(errno), NULL);
			close(fd);
			exit(1);
		case GET_PACKET_SHORT_READ:
			send_irc_reply(IRC_ERR_UNKNOWNERROR, "Local packet short read", NULL);
			close(fd);
			exit(1);
		case GET_PACKET_TOO_LARGE:
			send_irc_reply(IRC_ERR_UNKNOWNERROR, "Received local packet too large", NULL);
			close(fd);
			exit(1);
		case GET_PACKET_OUT_OF_MEMORY:
			send_irc_reply(IRC_ERR_UNKNOWNERROR, "Out of memory", NULL);
			close(fd);
			exit(1);
		case GET_PACKET_INCOMPLETE:
			syslog(LOG_INFO, "incomplete packet received, read %zu bytes, total %zu bytes; will continue later\n",
				buffer.read_length, buffer.total_length);
			return;
		case 0:
			break;
		default:
			send_irc_reply(IRC_ERR_UNKNOWNERROR, "Internal error", NULL);
			syslog(LOG_ERR, "Unknown error %d from get_local_packet", e);
			abort();
	}
	switch(packet->type) {
		case SSHOUT_LOCAL_DISPATCH_MESSAGE:
			send_irc_message((struct local_message *)packet->data);
			break;
		case SSHOUT_LOCAL_ONLINE_USERS_INFO:
			send_irc_online_users((struct local_online_users_info *)packet->data);
			break;
		case SSHOUT_LOCAL_USER_ONLINE:
			send_irc_user_join((char *)packet->data);
			//send_irc_user_mode_change((char *)packet->data, "+wr");
			break;
		case SSHOUT_LOCAL_USER_OFFLINE:
			send_irc_user_quit((char *)packet->data);
			break;
		case SSHOUT_LOCAL_USER_NOT_FOUND:
			send_irc_reply(IRC_ERR_NOSUCHNICK, (char *)packet->data, "User not found", NULL);
			break;
		default:
			syslog(LOG_WARNING, "Unknown local packet type %d", packet->type);
			break;
	}
	free(packet);
}

static char input_buffer[512];
static int ss;

static void client_irc_do_stdin(int fd) {
	int s;
	do {
		s = read(STDIN_FILENO, input_buffer + ss, sizeof input_buffer - ss);
	} while(s < 0 && errno == EINTR);
	if(s < 0) {
		if(errno == EAGAIN) return;
		perror("read");
		exit(1);
	}
	if(!s) {
		exit(0);
	}
	int skip_len = 0;
	char *lf, *last_lf = NULL;
	while((lf = memchr(input_buffer + ss + skip_len, '\n', s - skip_len)) && lf > input_buffer + 1 && lf[-1] == '\r') {
		int line_len = lf - input_buffer - skip_len - 1;	// Does not include \r\n
		do_irc_line(fd, input_buffer + skip_len, line_len);
		skip_len += line_len + 2;
		last_lf = lf;
	}
	ss += s - skip_len;
	if(last_lf) memmove(input_buffer, last_lf + 1, ss);
	if(ss == sizeof input_buffer) {
		//sync_write(STDOUT_FILENO, "ERROR :Closing Link: line too long\r\n", 35);
		send_irc_line("ERROR :Closing Link: line too long");
		exit(1);
	}
}

void client_irc_get_actions(struct client_frontend_actions *a) {
	a->init_io = client_irc_init;
	a->do_local_packet = client_irc_do_local_packet;
	a->do_stdin = client_irc_do_stdin;
	a->do_after_signal = NULL;
	a->do_tick = NULL;
}

#endif
