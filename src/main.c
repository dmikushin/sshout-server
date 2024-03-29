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
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void print_usage(const char *name) {
  fprintf(stderr, "Usage: %s [-c <user-name>]\n", name);
}

int main(int argc, char **argv) {
  uid_t myuid = getuid();
  uid_t myeuid = geteuid();
  if (myeuid == 0) {
    fprintf(stderr, "%s: This program shouldn't be run under effective root\n",
            argv[0]);
    return 1;
  }
  if (myuid != myeuid) {
    fprintf(stderr,
            "%s: Real user ID (%u) does not equal to effective user ID (%u)\n",
            argv[0], myuid, myeuid);
    return 1;
  }

  struct passwd *mypw = getpwuid(myuid);
  if (!mypw) {
    perror("getpwuid");
    return 1;
  }

  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "%s: HOME not set\n", argv[0]);
    return 1;
  }
  if (strcmp(home, mypw->pw_dir)) {
    fprintf(stderr, "%s: HOME=\"%s\" does not equal to \"%s\"\n", argv[0], home,
            mypw->pw_dir);
    return 1;
  }

  struct sockaddr_un sockaddr = {.sun_family = AF_UNIX};
  size_t home_len = strlen(home);
  if (home_len + 1 + sizeof SOCKET_NAME > sizeof sockaddr.sun_path) {
    fprintf(stderr, "home path too long (%zu bytes)\n", home_len);
    return 1;
  }
  memcpy(sockaddr.sun_path, home, home_len);
  sockaddr.sun_path[home_len] = '/';
  memcpy(sockaddr.sun_path + home_len + 1, SOCKET_NAME, sizeof SOCKET_NAME);

  if (chdir(home) < 0) {
    perror(home);
    return 1;
  }

  if (argc == 3 && strcmp(argv[1], "-c") == 0)
    return client_mode(&sockaddr, argv[2]);
  if (argc != 1) {
    print_usage(argv[0]);
    return 255;
  }
  return server_mode(&sockaddr);
}
