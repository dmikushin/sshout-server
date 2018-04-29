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
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

static int adduser_command(int argc, char **argv) {
	return -1;
}

static struct subcommand {
	const char *name;
	int (*func)(int, char **);
} commands[] = {
#define SUBCOMMAND(N) { #N, N##_command }
	SUBCOMMAND(adduser),
#undef SUBCOMMAND
	{ NULL, NULL }
};

static void print_commands() {
	struct subcommand *c = commands;
	fputs("Following subcommands are available:\n", stderr);
	while(c->name) {
		fprintf(stderr, "	%s\n", c->name);
		c++;
	}
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
