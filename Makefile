ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS += -Wall -Wno-switch -Wno-char-subscripts -O1
#LIBS += 

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

sshoutcfg:	$(SSHOUTCFG_OBJCTS)
	$(CC) $^ -o $@ $(SSHOUTCFG_LIBS) $(LIBS)

sshoutd:	$(SSHOUTD_OBJECTS)
	$(CC) $^ -o $@ $(SSHOUTD_LIBS) $(LIBS)

clean:
	rm -f $(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS) sshoutcfg sshoutd

install:	all
	[ -d "$(LIBEXECDIR)" ] || mkdir -p "$(LIBEXECDIR)"
	[ -d "$(SBINDIR)" ] || mkdir -p "$(SBINDIR)"
	[ -d "$(DATADIR)" ] || mkdir -p "$(DATADIR)"
	[ -d "$(MANDIR)/man8" ] || mkdir -p "$(MANDIR)/man8"
	cp sshoutd "$(LIBEXECDIR)/"
	cp sshoutcfg "$(SBINDIR)/"
	cp sshoutcfg.8 "$(MANDIR)/man8/"
