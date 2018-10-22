/* Secure Shout Host Oriented Unified Talk
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
#include "base64.h"
#include "misc.h"
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "file-helpers.h"
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <mhash.h>

static void print_usage(const char *);

static enum key_types {
	KEY_INVALID = -1,
	KEY_RSA,
	KEY_DSA,
	KEY_ECDSA,
	KEY_ED25519
} get_key_type(const char *key, size_t type_len) {
	switch(type_len) {
		case 3:
			if(strncasecmp(key, "RSA", 3) == 0) return KEY_RSA;
			if(strncasecmp(key, "DSA", 3) == 0) return KEY_DSA;
			return KEY_INVALID;
		case 5:
			if(strncasecmp(key, "ECDSA", 5) == 0) return KEY_ECDSA;
			return KEY_INVALID;
		case 7:
			if(strncasecmp(key, "ED25519", 7) == 0) return KEY_ED25519;
			if(memcmp(key, "ssh-rsa", 7) == 0) return KEY_RSA;
			if(memcmp(key, "ssh-dss", 7) == 0) return KEY_DSA;
			return KEY_INVALID;
		case 11:
			if(memcmp(key, "ssh-ed25519", 11) == 0) return KEY_ED25519;
			return KEY_INVALID;
		case 19:
			if(memcmp(key, "ecdsa-sha2-nistp", 16) == 0) {
				if(memcmp(key + 16, "256", 3) == 0 ||
				   memcmp(key + 16, "384", 3) == 0 ||
				   memcmp(key + 16, "521", 3) == 0) {
					return KEY_ECDSA;
				}
			}
			return KEY_INVALID;
	}
	return KEY_INVALID;
}

static const char *key_type_to_string(enum key_types t) {
	switch(t) {
		case KEY_RSA: return "RSA";
		case KEY_DSA: return "DSA";
		case KEY_ECDSA: return "ECDSA";
		case KEY_ED25519: return "ED25519";
		default: return NULL;
	}
}

static int get_length_and_type_string_length_of_key_in_base64(const char *key, size_t *base64_len, size_t *type_len, char *buffer, size_t buffer_size) {
#if 0
	const char *space = strchr(key, ' ');
	*base64_len = space ? space - key : strlen(key);
#else
	*base64_len = 0;
	while(key[*base64_len] && key[*base64_len] != ' ') (*base64_len)++;
#endif
	int blob_len = base64_decode(key, *base64_len, buffer, buffer_size);
	if(blob_len == -1) {
		fputs("Invalid key: invalid BASE64 encoding\n", stderr);
		return -1;
	}
	if(blob_len < 4) {
		fputs("Invalid key: too short\n", stderr);
		return -1;
	}
	*type_len = ntohl(*(uint32_t *)buffer);
	if(*type_len > (size_t)blob_len - 4) {
		fprintf(stderr, "Invalid key: key type string length %u too long\n", (unsigned int)*type_len);
		return -1;
	}
	return 0;
}

static unsigned int nlines;

static int read_user_info(FILE *f, char **name, char **public_key, char **comment, enum key_types *key_type, size_t *line_len) {
	char line[4096];
	while(1) {
		nlines++;
		int len = fgetline(f, line, sizeof line);
		if(len == -2) {
			int c;
			fprintf(stderr, "Warning: line %u in file " USER_LIST_FILE " is too long, skipping\n", nlines);
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
			fprintf(stderr, "Warning: cannot find '\"' at line %u in file " USER_LIST_FILE "\n", nlines);
			continue;
		}
		*q1 = 0;
		if(q1 - p < 8 || strcmp(q1 - 8, "command=") || strchr(p, ' ')) {
			fprintf(stderr, "Warning: syntax error in file " USER_LIST_FILE " line %u\n", nlines);
			continue;
		}
		q1++;
		char *q2 = strchr(q1, '"');
		if(!q2) {
			fprintf(stderr, "Warning: unmatched '\"' in file " USER_LIST_FILE " line %u\n", nlines);
			continue;
		}
		char *space = strchr(q2 + 1, ' ');
		if(!space) {
			fprintf(stderr, "Warning: syntax error in file " USER_LIST_FILE " line %u\n", nlines);
			continue;
		}
		size_t user_name_len = q2 - q1;
		if(!user_name_len) {
			fprintf(stderr, "Warning: empty user name in file " USER_LIST_FILE " line %u\n", nlines);
			continue;
		}
		char *type_string = space + 1;
		space = strchr(type_string, ' ');
		if(!space) {
			fprintf(stderr, "Warning: syntax error in file " USER_LIST_FILE " line %u\n", nlines);
			continue;
		}
		size_t type_len = space - type_string;
		enum key_types key_type_1 = get_key_type(type_string, type_len);
		if(key_type_1 == KEY_INVALID) {
			*space = 0;
			fprintf(stderr, "Warning: invalid key type '%s' in file " USER_LIST_FILE " line %u\n", type_string, nlines);
			continue;
		}
		const char *base64 = space + 1;
		char buffer[32];
		size_t base64_len, inner_type_len;
		if(get_length_and_type_string_length_of_key_in_base64(base64, &base64_len, &inner_type_len, buffer, sizeof buffer) < 0) return 1;
		char *inner_key_type_string = buffer + 4;
		enum key_types key_type_2 = get_key_type(inner_key_type_string, inner_type_len);
		if(key_type_2 == KEY_INVALID) {
			inner_key_type_string[inner_type_len] = 0;
			fprintf(stderr, "Warning: invalid key type '%s' from BASE64 in file " USER_LIST_FILE " line %u\n", inner_key_type_string, nlines);
			continue;
		}
		if(key_type_2 != key_type_1) {
			fprintf(stderr, "Warning: key type didn't match in file " USER_LIST_FILE " line %u; key ignored\n", nlines);
			continue;
		}
		*name = malloc(user_name_len + 1);
		if(!*name) {
			fprintf(stderr, "Error: allocate %zu bytes failed when processing file " USER_LIST_FILE " line %u\n", user_name_len + 1, nlines);
			return -1;
		}
		memcpy(*name, q1, user_name_len);
		(*name)[user_name_len] = 0;
		*public_key = malloc(type_len + 1 + base64_len + 1);
		if(!*public_key) {
			fprintf(stderr, "Error: out of memory when processing file " USER_LIST_FILE " line %u\n", nlines);
			return -1;
		}
		memcpy(*public_key, type_string, type_len + 1 + base64_len);
		(*public_key)[type_len + 1 + base64_len] = 0;
		if(comment) {
			if(base64[base64_len] == ' ') {
				*comment = strdup(base64 + base64_len + 1);
				if(!*comment) {
					fprintf(stderr, "Error: out of memory when processing file " USER_LIST_FILE " line %u\n", nlines);
					return -1;
				}
			} else *comment = NULL;
		}
		if(key_type) *key_type = key_type_1;
		if(line_len) *line_len = len;
		return 0;
	}
}

static int remove_ssh_rc_file() {
	struct stat st;
	if(lstat(".ssh/rc", &st) < 0) {
		if(errno == ENOENT) return 0;
		perror(".ssh/rc");
		return -1;
	}
	if(S_ISDIR(st.st_mode)) {
		fputs("'.ssh/rc' exists, and it is a directory!\n", stderr);
		return -1;
	}
	fputs("sshout shouldn't have a SSH RC file '.ssh/rc'; removing\n", stderr);
	if(unlink(".ssh/rc") < 0) {
		perror("unlink: .ssh/rc");
		return -1;
	}
	return 0;
}

static int ask_confirm() {
	char answer[16];
	do {
		int len = fgetline(stdin, answer, sizeof answer);
		// Ignore line too long error
		if(len == -1 || strncasecmp(answer, "no", 2) == 0 || strncmp(answer, "不", 3) == 0 || strcmp(answer, "否") == 0) {
			return 0;
		}
	} while(strncasecmp(answer, "yes", 3) && strncmp(answer, "是", 3) && strncmp(answer, "好", 3) && strcmp(answer, "可以"));
	return 1;
}

static int adduser_command(int argc, char **argv) {
	char *key = NULL;
	int force = 0;
	while(1) {
		int c = getopt(argc, argv, "a:fh");
		if(c == -1) break;
		switch(c) {
			case 'a':
				if(strchr(optarg, '\n')) {
					fputs("Key string shouldn't have new line\n", stderr);
					return 1;
				}
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
	if(argc - optind != 1) {
		print_usage(argv[0]);
		return -1;
	}
	const char *user = argv[optind];
	if(!is_valid_user_name(user)) {
		fprintf(stderr, "Invalid user name '%s'\n", user);
		return 1;
	}
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

	char *space = strchr(key, ' ');
	if(space) {
		size_t type_len = space - key;
		enum key_types key_type = get_key_type(key, type_len);
		if(key_type == KEY_INVALID) {
			*space = 0;
			fprintf(stderr, "Invalid key type '%s'\n", key);
			return 1;
		}
		const char *base64 = space + 1;
		char buffer[32];
		size_t base64_len, inner_type_len;
		if(get_length_and_type_string_length_of_key_in_base64(base64, &base64_len, &inner_type_len, buffer, sizeof buffer) < 0) return 1;
		char *inner_key_type_string = buffer + 4;
		enum key_types inner_key_type = get_key_type(inner_key_type_string, inner_type_len);
		if(inner_key_type == KEY_INVALID) {
			inner_key_type_string[inner_type_len] = 0;
			fprintf(stderr, "Invalid key type '%s'\n", inner_key_type_string);
			return 1;
		}
		if(inner_key_type != key_type) {
			fputs("Invalid key: key type didn't match\n", stderr);
			return 1;
		}
		// 'space' is now point to the second space if exists
		space = key + type_len + 1 + base64_len;
		if(*space == ' ') *space = 0;
		else space = NULL;
	} else {
		char buffer[32];
		size_t base64_len, type_len;
		if(get_length_and_type_string_length_of_key_in_base64(key, &base64_len, &type_len, buffer, sizeof buffer) < 0) return 1;
		char *key_type_string = buffer + 4;
		enum key_types key_type = get_key_type(key_type_string, type_len);
		if(key_type == KEY_INVALID) {
			key_type_string[type_len] = 0;
			fprintf(stderr, "Invalid key type '%s'\n", key_type_string);
			return 1;
		}
		char *type_and_key_in_base64 = malloc(type_len + 1 + base64_len + 1);
		if(!type_and_key_in_base64) {
			perror("malloc");
			return 1;
		}
		memcpy(type_and_key_in_base64, key_type_string, type_len);
		type_and_key_in_base64[type_len] = ' ';
		memcpy(type_and_key_in_base64 + type_len + 1, key, base64_len);
		type_and_key_in_base64[type_len + 1 + base64_len] = 0;
		free(key);
		key = type_and_key_in_base64;
	}

	struct stat st;
	if(stat(".ssh", &st) == 0) {
		if(!S_ISDIR(st.st_mode)) {
			free(key);
			fputs("'.ssh' is not a directory\n", stderr);
			return 1;
		}
		uid_t myuid = getuid();
		if(st.st_uid != myuid) {
			free(key);
			fprintf(stderr, "'.ssh' is not owned by sshout (%u != %u)\n", st.st_uid, myuid);
			return 1;
		}
		if(st.st_mode & S_IWOTH) {
			fputs("'.ssh' is global writable\n", stderr);
			if(chmod(".ssh", st.st_mode & ~(S_IWOTH)) < 0) {
				perror("chmod: .ssh");
				free(key);
				return 1;
			}
			fputs("fixed\n", stderr);
		}
		if(remove_ssh_rc_file() < 0) {
			free(key);
			fputs("Cannot continue\n", stderr);
			return 1;
		}
	} else if(mkdir(".ssh", 0755) < 0) {
		perror("mkdir: .ssh");
		free(key);
		return 1;
	}

	FILE *f = fopen(USER_LIST_FILE, "a+");
	if(!f) {
		perror(USER_LIST_FILE);
		free(key);
		return 1;
	}

#ifndef __GLIBC__
	if(fseek(f, 0, SEEK_SET) < 0) {
		perror("fseek");
		free(key);
		return 1;
	}
#endif

	int existing_count = 0;
	{
		char *user_name, *public_key;
		while(read_user_info(f, &user_name, &public_key, NULL, NULL, NULL) == 0) {
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
			fprintf(stderr, "Are you sure you want to add this key for user %s? ", user);
			if(!ask_confirm()) {
				fputs("Operation canceled\n", stderr);
				free(key);
				return 1;
			}
		}
	}

	if(space) *space = ' ';
	if(fprintf(f, "command=\"%s\",no-agent-forwarding,no-port-forwarding %s\n", user, key) < 0) {
		perror("fprintf");
		free(key);
		return 1;
	}
	free(key);
	return 0;
}

static int removeuser_command(int argc, char **argv) {
	int force = 0;
	while(1) {
		int c = getopt(argc, argv, "fh");
		if(c == -1) break;
		switch(c) {
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
	if(argc - optind != 1) {
		print_usage(argv[0]);
		return -1;
	}
	const char *user = argv[optind];
	if(!is_valid_user_name(user)) {
		fprintf(stderr, "Invalid user name '%s'\n", user);
		return 1;
	}

	FILE *f = fopen(USER_LIST_FILE, "r+");
	if(!f) {
		perror(USER_LIST_FILE);
		return 1;
	}

	struct line_info {
		long int end_offset;
		size_t length;
	} *match_lines = NULL;
	size_t line_count = 0, match_lines_allocated_size = 0;
	char *user_name, *public_key;
	size_t line_len;
	while(read_user_info(f, &user_name, &public_key, NULL, NULL, &line_len) == 0) {
		if(strcmp(user, user_name) == 0) {
			if(line_count * sizeof(struct line_info) >= match_lines_allocated_size) {
				match_lines = realloc(match_lines, match_lines_allocated_size += 2 * sizeof(struct line_info));
				if(!match_lines) {
					perror("realloc");
					return 1;
				}
			}
			match_lines[line_count].end_offset = ftell(f);
			match_lines[line_count].length = line_len;
			line_count++;
		}
		free(user_name);
		free(public_key);
	}

	if(!line_count) {
		fclose(f);
		fprintf(stderr, "User %s not found\n", user);
		return 1;
	}

	if(line_count == 1) {
		if(!force) {
			fprintf(stderr, "Remove user %s from SSHOUT user list? ", user);
			if(!ask_confirm()) {
				fclose(f);
				fputs("Operation canceled\n", stderr);
				return 1;
			}
		}
		if(fseek(f, match_lines->end_offset, SEEK_SET) < 0 ||
		fbackwardoverwrite(f, match_lines->length + 1) < 0) {
			perror("Failed to remove user");
			fclose(f);
			return 1;
		}
		if(fclose(f) == EOF) {
			perror("fclose");
			return 1;
		}
		return 0;
	} else {
		if(!force) {
			fprintf(stderr, "User %s have %zu public keys registered in the user list\n", user, line_count);
			fprintf(stderr, "If you want to remove only some of the user's keys, edit file '%s/ " USER_LIST_FILE "' manually\n",
				getenv("HOME"));
			fprintf(stderr, "Remove all keys for user %s? ", user);
			if(!ask_confirm()) {
				fclose(f);
				fputs("Operation canceled\n", stderr);
				return 1;
			}
		}
		unsigned int i = line_count;
		do {
			i--;
			if(fseek(f, match_lines[i].end_offset, SEEK_SET) < 0 ||
			fbackwardoverwrite(f, match_lines[i].length + 1) < 0) {
				perror("Failed to remove user");
				fprintf(stderr, "when removing key %u from user list\n", i);
				fclose(f);
				return 1;
			}
		} while(i > 0);
		if(fclose(f) == EOF) {
			perror("fclose");
			return 1;
		}
		fprintf(stderr, "Removed %zu keys for user %s\n", line_count, user);
		return 0;
	}
}

static int listuser_command(int argc, char **argv) {
	hashid hash_type = -1;
	while(1) {
		int c = getopt(argc, argv, "h:");
		if(c == -1) break;
		switch(c) {
			case 'h':
				if(strcmp(optarg, "md5") == 0) hash_type = MHASH_MD5;
				else if(strcmp(optarg, "sha256") == 0) hash_type = MHASH_SHA256;
				else {
					fprintf(stderr, "Invalid hash algorithm '%s'\n", optarg);
					return -1;
				}
				break;
			case '?':
				print_usage(argv[0]);
				return -1;
		}
	}

	if(remove_ssh_rc_file() < 0) {
		fputs("Warning: configuration error left unresolved\n", stderr);
	}

	FILE *f = fopen(USER_LIST_FILE, "r");
	if(!f) {
		perror(USER_LIST_FILE);
		return 1;
	}

	char *user_name, *public_key, *comment;
	while(read_user_info(f, &user_name, &public_key, &comment, NULL, NULL) == 0) {
		//printf("User \"%s\", Public key \"%s\"", user_name, public_key);
		printf("User \"%s\", ", user_name);
		if((int)hash_type == -1) {
			printf("Public key \"%s\"", public_key);
		} else {
			MHASH h = mhash_init(hash_type);
			if(h == MHASH_FAILED) {
				fputs("Cannot start hash public key\n", stderr);
				return 1;
			}
			char *space = strchr(public_key, ' ');
			if(!space) {
				fputs("Invalid key\n", stderr);
				return 1;
			}
			char *base64 = space + 1;
			int len = strlen(base64);
			char buffer[len];
			len = base64_decode(base64, len, buffer, sizeof buffer);
			if(len < 0) {
				fputs("Invalid BASE64 encoding\n", stderr);
				return 1;
			}
			if(len < 8) {
				fputs("Invalid key\n", stderr);
				return 1;
			}
			size_t type_len = ntohl(*(uint32_t *)buffer);
			if(type_len > len - 4) {
				fputs("Invalid key\n", stderr);
				return 1;
			}
			printf("Public key fingerprint %s ", key_type_to_string(get_key_type(buffer + 4, type_len)));
			mhash(h, buffer, len);
			unsigned char *hash = mhash_end(h);
			unsigned int i = 0, hash_len = mhash_get_block_size(hash_type);
			if(hash_type == MHASH_SHA256) {
				char buffer[44];
				len = base64_encode(hash, hash_len, buffer, sizeof buffer, 0);
				fputs(len < 0 ? "Cannot encode SHA-256 fingerprint" : buffer, stdout);
			} else while(i < hash_len) {
				if(i) putchar(':');
				printf("%.2hhx", hash[i++]);
			}
		}
		if(comment) printf(", Comment \"%s\"", comment);
		putchar('\n');
		free(user_name);
		free(public_key);
		free(comment);
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
				print_usage(argv[0]);
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
	SUBCOMMAND(adduser, "[-a <public-key-in-base64>] [-f] <user-name>"),
	SUBCOMMAND(removeuser, "[-f] <user-name>"),
	SUBCOMMAND(listuser, "[-h {md5|sha256}]"),
	SUBCOMMAND(getmotd, ""),
	SUBCOMMAND(setmotd, "[-m <message> | -d]"),
#undef SUBCOMMAND
	{ NULL, NULL, NULL }
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
