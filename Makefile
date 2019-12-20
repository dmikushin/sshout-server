ifeq ($(CC),cc)
CC := $(shell gcc --version > /dev/null 2>&1 && gcc -v 2>&1 | grep -q ^gcc && echo gcc || echo cc)
endif
INSTALL ?= install

CFLAGS += -Wall -Wno-switch -Wno-pointer-to-int-cast -O1
#LIBS += 

#ifneq ($(wildcard .git/HEAD),)
#CFLAGS += -D GIT_COMMIT=\"`cut -c -7 ".git/\`sed 's/^ref: //' .git/HEAD\`"`\"
#endif

PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/lib/sshout
SBINDIR ?= $(PREFIX)/sbin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(DATADIR)/man

SSHOUTCFG_OBJCTS = base64.o file-helpers.o misc.o sshoutcfg.o syncrw.o
SSHOUTD_OBJECTS = api-packet.o client.o client-api.o client-cli.o client-irc.o file-helpers.o local-packet.o main.o misc.o server.o syncrw.o
SSHOUTCFG_LIBS = -lmhash
SSHOUTD_LIBS = -lreadline

all:	sshoutcfg sshoutd

build-info.h:
	{ [ -f .git/HEAD ] && printf "#define GIT_COMMIT \"%s\"\\n" "`cut -c -7 \".git/\`sed 's/^ref: //' .git/HEAD\`\"`" || true; } > $@

common.h:	build-info.h

$(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS):	common.h

sshoutcfg:	$(SSHOUTCFG_OBJCTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(SSHOUTCFG_LIBS) $(LIBS)

sshoutd:	$(SSHOUTD_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(SSHOUTD_LIBS) $(LIBS)

clean:
	rm -f build-info.h $(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS) sshoutcfg sshoutd

install:	all
	[ -d "$(DESTDIR)$(LIBEXECDIR)" ] || mkdir -p "$(DESTDIR)$(LIBEXECDIR)"
	[ -d "$(DESTDIR)$(SBINDIR)" ] || mkdir -p "$(DESTDIR)$(SBINDIR)"
	[ -d "$(DESTDIR)$(DATADIR)" ] || mkdir -p "$(DESTDIR)$(DATADIR)"
	[ -d "$(DESTDIR)$(MANDIR)/man8" ] || mkdir -p "$(DESTDIR)$(MANDIR)/man8"
	$(INSTALL) -m 755 sshoutd "$(DESTDIR)$(LIBEXECDIR)/"
	$(INSTALL) -m 755 sshoutcfg "$(DESTDIR)$(SBINDIR)/"
	$(INSTALL) -m 644 sshoutcfg.8 "$(DESTDIR)$(MANDIR)/man8/"

.PHONY:	build-info.h clean install
