ifeq ($(CC),cc)
CC := gcc
endif
INSTALL ?= install

CFLAGS += -Wall -Wno-switch -Wno-char-subscripts -O1
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
	{ [ -f .git/HEAD ] && printf "#define GIT_COMMIT \"%s\"\\n" "`cut -c -7 ".git/\`sed 's/^ref: //' .git/HEAD\`"`"; } > $@

common.h:	build-info.h

$(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS):	common.h

sshoutcfg:	$(SSHOUTCFG_OBJCTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(SSHOUTCFG_LIBS) $(LIBS)

sshoutd:	$(SSHOUTD_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(SSHOUTD_LIBS) $(LIBS)

clean:
	rm -f build-info.h $(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS) sshoutcfg sshoutd

install:	all
	[ -d "$(LIBEXECDIR)" ] || mkdir -p "$(LIBEXECDIR)"
	[ -d "$(SBINDIR)" ] || mkdir -p "$(SBINDIR)"
	[ -d "$(DATADIR)" ] || mkdir -p "$(DATADIR)"
	[ -d "$(MANDIR)/man8" ] || mkdir -p "$(MANDIR)/man8"
	$(INSTALL) -m 755 sshoutd "$(LIBEXECDIR)/"
	$(INSTALL) -m 755 sshoutcfg "$(SBINDIR)/"
	$(INSTALL) -m 644 sshoutcfg.8 "$(MANDIR)/man8/"
