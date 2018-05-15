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
#include "syncrw.h"
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

static void print_usage(const char *);

static int fgetline(FILE *f, char *line, size_t len) {
	size_t i = 0;
	int c;
	while((c = fgetc(f)) != '\n') {
		if(c == EOF) {
			if(!i) return -1;
			break;
		}
		if(i >= len - 1) return -2;
		line[i++] = c;
	}
	line[i] = 0;
	return i;
}

static int read_user_info(FILE *f, char **name, char **public_key) {
	int i = 0;
	char line[4096];
	while(1) {
		i++;
		int len = fgetline(f, line, sizeof line);
		if(len == -2) {
			int c;
			fprintf(stderr, "Warning: line %u in file " USER_LIST_FILE " is too long, skipping\n", i);
			while((c = fgetc(f)) != EOF && c != '\n');
			continue;
		}
		if(len < 0) return -1;	// EOF
		if(len == 0 || *line == '#') continue;
		char *p = line;
		while(*p && (*p == ' ' || *p == '	')) p++;
		if(!*p) continue;
		char *q1 = strchr(p, '"');
		if(!q1) {
			fprintf(stderr, "Warning: cannot find '\"' at line %u in file " USER_LIST_FILE "\n", i);
			continue;
		}
		*q1 = 0;
		if(q1 - p < 8 || strcmp(q1 - 8, "command=") || strchr(p, ' ')) {
			fprintf(stderr, "Warning: syntax error in file " USER_LIST_FILE " line %u\n", i);
			continue;
		}
		q1++;
		char *q2 = strchr(q1, '"');
		if(!q2) {
			fprintf(stderr, "Warning: unmatched '\"' in file " USER_LIST_FILE " line %u\n", i);
			continue;
		}
		char *space = strchr(q2 + 1, ' ');
		if(!space) {
			fprintf(stderr, "Warning: syntax error in file " USER_LIST_FILE " line %u\n", i);
			continue;
		}
		size_t user_name_len = q2 - q1;
		if(!user_name_len) {
			fprintf(stderr, "Warning: empty user name in file " USER_LIST_FILE " line %u\n", i);
			continue;
		}
		*name = malloc(user_name_len + 1);
		if(!*name) {
			fprintf(stderr, "Error: allocate %zu bytes failed when processing file " USER_LIST_FILE " line %u\n", user_name_len + 1, i);
			return -1;
		}
		memcpy(*name, q1, user_name_len);
		(*name)[user_name_len] = 0;
		*public_key = strdup(space + 1);
		if(!*public_key) {
			fprintf(stderr, "Error: out of memory when processing file " USER_LIST_FILE " line %u\n", i);
			return -1;
		}
		return 0;
	}
}

static int adduser_command(int argc, char **argv) {
	char *key = NULL;
	int force = 0;
	while(1) {
		int c = getopt(argc, argv, "a:fh");
		if(c == -1) break;
		switch(c) {
			case 'a':
				key = strdup(optarg);
				if(!key) {
					perror("strdup");
					return 1;
				}
				break;
			case 'f':
				force = 1;
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			case '?':
				return -1;
		}
	}
	//fprintf(stderr, "optind = %d, argc = %d\n", optind, argc);
	if(argc - optind != 1) {
		print_usage(argv[0]);
		return -1;
	}
	const char *user = argv[optind];
	if(!key) {
		key = malloc(4096);
		if(!key) {
			perror("malloc");
			return 1;
		}
		fprintf(stderr, "Input public key for %s: ", user);
		if(fgetline(stdin, key, 4096) == -2) {
			free(key);
			fputs("Public key too long\n", stderr);
			return 1;
		}
	}	

	// TODO: verify the key format

	FILE *f = fopen(USER_LIST_FILE, "a+");
	if(!f) {
		perror(USER_LIST_FILE);
		free(key);
		return 1;
	}

	int existing_count = 0;
	{
		char *user_name, *public_key;
		while(read_user_info(f, &user_name, &public_key) == 0) {
			if(strcmp(key, public_key) == 0) {
				free(key);
				fprintf(stderr, "This public key is already used by user %s.\n"
					"Are you pasted wrong key?\n", user_name);
				free(user_name);
				free(public_key);
				return 1;
			}
			if(strcmp(user, user_name) == 0) existing_count++;
			free(user_name);
			free(public_key);
		}
	}
	if(existing_count) {
		fprintf(stderr, "%d key%s already exist for user %s\n", existing_count, existing_count > 1 ? "s" : "", user);
		if(!force) {
			char answer[16];
			fprintf(stderr, "Are you sure you want to add this key for user %s? ", user);
			do {
				int len = fgetline(stdin, answer, sizeof answer);
				// Ignore line too long error
				if(len == -1 || strncasecmp(answer, "no", 2) == 0 || strncmp(answer, "不", 3) == 0 || strcmp(answer, "否") == 0) {
					fputs("Operation canceled\n", stderr);
					return 1;
				}
			} while(strncasecmp(answer, "yes", 3) && strncmp(answer, "是", 3) && strncmp(answer, "好", 3) && strcmp(answer, "可以"));
		}
	}

	if(fprintf(f, "command=\"%s\",no-agent-forwarding,no-port-forwarding %s\n", user, key) < 0) {
		perror("fprintf");
		free(key);
		return 1;
	}
	free(key);
	return -1;
}

static int listuser_command(int argc, char **argv) {
	FILE *f = fopen(USER_LIST_FILE, "r");
	if(!f) {
		perror(USER_LIST_FILE);
		return 1;
	}

/*
	char line[4096];
	while(fgetline(f, line, sizeof line) > 0) {
		fprintf(stderr, "line = \"%s\"\n", line);
	}
*/
	char *user_name, *public_key;
	while(read_user_info(f, &user_name, &public_key) == 0) {
		fprintf(stderr, "User \"%s\", Public key \"%s\"\n", user_name, public_key);
		free(user_name);
		free(public_key);
	}
	return 0;
}

static int getmotd_command(int argc, char **argv) {
	char buffer[4096];
	int fd = open(SSHOUT_MOTD_FILE, O_RDONLY);
	if(fd == -1) {
		perror(SSHOUT_MOTD_FILE);
		return 1;
	}
	while(1) {
		int s = sync_read(fd, buffer, sizeof buffer);
		if(s < 0) {
			perror("read");
			return 1;
		}
		if(!s) return 0;
		s = sync_write(STDOUT_FILENO, buffer, s);
		if(s < 0) {
			perror("write");
			return 1;
		}
	}
}

static int setmotd_command(int argc, char **argv) {
	const char *message = NULL;
	int need_del = 0;
	while(1) {
		int c = getopt(argc, argv, "m:dh");
		if(c == -1) break;
		switch(c) {
			case 'm':
				message = optarg;
				break;
			case 'd':
				need_del = 1;
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			case '?':
				return -1;
		}
	}
	if(need_del) {
		if(message) {
			fputs("Option '-d' cannot be used together with '-m'\n", stderr);
			return -1;
		}
		if(unlink(SSHOUT_MOTD_FILE) < 0) {
			perror(SSHOUT_MOTD_FILE);
			return 1;
		}
		return 0;
	}
	int fd = creat(SSHOUT_MOTD_FILE, 0600);
	if(fd == -1) {
		perror(SSHOUT_MOTD_FILE);
		return 1;
	}
	if(message) {
		size_t len = strlen(message);
		int s = sync_write(fd, message, len);
		if(s < 0) {
			perror("write");
			return 1;
		}
		if(len && message[len - 1] != '\n') {
			char new_line = '\n';
			if(sync_write(fd, &new_line, 1) < 0) {
				perror("write");
				return 1;
			}
		}
		return 0;
	} else {
		char buffer[4096];
		if(isatty(STDIN_FILENO)) fputs("Type message below:\n", stderr);
		while(1) {
			int s = read(STDIN_FILENO, buffer, sizeof buffer);
			if(s < 0) {
				if(errno == EINTR) continue;
				perror("read");
				return 1;
			}
			if(!s) return 0;
			s = sync_write(fd, buffer, s);
			if(s < 0) {
				perror("write");
				return 1;
			}
		}
	}
}

static struct subcommand {
	const char *name;
	const char *usage;
	int (*func)(int, char **);
} commands[] = {
#define SUBCOMMAND(N,U) { #N, U, N##_command }
	SUBCOMMAND(adduser, "[-a <public-key>] [-f] <user-name>"),
	SUBCOMMAND(listuser, ""),
	SUBCOMMAND(getmotd, ""),
	SUBCOMMAND(setmotd, "[-m <message> | -d]"),
#undef SUBCOMMAND
	{ NULL, NULL }
};

static void print_commands() {
	struct subcommand *c = commands;
	fputs("Following subcommands are available:\n", stderr);
	while(c->name) {
		fprintf(stderr, "	%s %s\n", c->name, c->usage);
		c++;
	}
}

static void print_usage(const char *name) {
	struct subcommand *c = commands;
	while(c->name) {
		if(strcmp(c->name, name) == 0) {
			fprintf(stderr, "Usage: %s %s\n", name, c->usage);
			return;
		}
		c++;
	}
	fprintf(stderr, "Error: cannot find usage for command '%s'", name);
}

int main(int argc, char **argv) {
	struct passwd *pw = getpwnam("sshout");
	if(!pw) {
		fputs("sshout user account not exist\n", stderr);
		return 1;
	}
	if(pw->pw_uid == 0) {
		fputs("sshout user account have UID 0\n", stderr);
		return 1;
	}

	if(argc < 2) {
		print_commands();
		return -1;
	}

	//uid_t myuid = getuid();
	uid_t myeuid = geteuid();
	if(myeuid == 0) {
		if(setreuid(pw->pw_uid, pw->pw_uid) < 0) {
			perror("setreuid");
			return 1;
		}
	} else if(myeuid != pw->pw_uid) {
		fprintf(stderr, "Current effective UID %u doesn't equal to sshout user account\n", myeuid);
		return 1;
	}

	const char *home = pw->pw_dir;
	struct stat st;
	if(stat(home, &st) < 0) {
		perror(home);
		return 1;
	}
	if(st.st_uid != pw->pw_uid) {
		fprintf(stderr, "Home directory '%s' is not owned by sshout (expecting UID=%u, got %u)\n", home, pw->pw_uid, st.st_uid);
		return 1;
	}
	setenv("HOME", home, 1);
	if(chdir(home) < 0) {
		perror(home);
		return 1;
	}

	struct subcommand *c = commands;
	while(c->name) {
		if(strcmp(argv[1], c->name) == 0) return c->func(argc - 1, argv + 1);
		c++;
	}
	fprintf(stderr, "Unknown command '%s'\n", argv[1]);
	print_commands();
	return -1;
}
