ifeq ($(CC),cc)
CC := $(shell gcc --version > /dev/null 2>&1 && gcc -v 2>&1 | grep -q ^gcc && echo gcc || echo cc)
endif
INSTALL ?= install
MSGFMT ?= msgfmt

CFLAGS += -Wall -Wno-switch -Wno-pointer-to-int-cast -O1
#LIBS += 

#SOCKET_LIBS := -l socket
#NLS_LIBS := -l intl

PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/lib/sshout
SBINDIR ?= $(PREFIX)/sbin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(DATADIR)/man
LOCALEDIR ?= $(DATADIR)/locale

SSHOUTCFG_OBJCTS := base64.o file-helpers.o misc.o sshoutcfg.o syncrw.o
SSHOUTD_OBJECTS := api-packet.o client.o client-api.o client-cli.o client-irc.o file-helpers.o local-packet.o main.o misc.o server.o syncrw.o
SSHOUTCFG_LIBS = -l mhash
SSHOUTD_LIBS = -l readline $(SOCKET_LIBS)
ifdef NO_NLS
TRANSLATED_MESSAGES :=
CFLAGS += -D NO_NLS=1
else
TRANSLATED_MESSAGES := zh_CN.mo zh_TW.mo
SSHOUTCFG_LIBS += $(NLS_LIBS)
SSHOUTD_LIBS += $(NLS_LIBS)
endif

all:	sshoutcfg sshoutd $(TRANSLATED_MESSAGES)

build-info.h:
	{ [ -f .git/HEAD ] && printf "#define GIT_COMMIT \"%s\"\\n" "`cut -c -7 \".git/\`sed 's/^ref: //' .git/HEAD\`\"`" || true; } > $@

common.h:	build-info.h

$(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS):	common.h

sshoutcfg:	$(SSHOUTCFG_OBJCTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(SSHOUTCFG_LIBS) $(LIBS)

sshoutd:	$(SSHOUTD_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(SSHOUTD_LIBS) $(LIBS)

clean:
	rm -f build-info.h $(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS) sshoutcfg sshoutd $(TRANSLATED_MESSAGES)

install:	all
	[ -d "$(DESTDIR)$(LIBEXECDIR)" ] || mkdir -p "$(DESTDIR)$(LIBEXECDIR)"
	[ -d "$(DESTDIR)$(SBINDIR)" ] || mkdir -p "$(DESTDIR)$(SBINDIR)"
	[ -d "$(DESTDIR)$(DATADIR)" ] || mkdir -p "$(DESTDIR)$(DATADIR)"
	[ -d "$(DESTDIR)$(MANDIR)/man8" ] || mkdir -p "$(DESTDIR)$(MANDIR)/man8"
	$(INSTALL) -m 755 sshoutd "$(DESTDIR)$(LIBEXECDIR)/"
	$(INSTALL) -m 755 sshoutcfg "$(DESTDIR)$(SBINDIR)/"
	$(INSTALL) -m 644 sshoutcfg.8 "$(DESTDIR)$(MANDIR)/man8/"
ifndef NO_NLS
	for f in $(TRANSLATED_MESSAGES); do d="$(DESTDIR)$(LOCALEDIR)/$${f%.mo}/LC_MESSAGES"; [ -d "$$d" ] || mkdir -p "$$d" || exit; $(INSTALL) -m 644 $$f "$$d/sshout.mo"; done
endif

%.mo:	po/%.po
	$(MSGFMT) $< -o $@

.PHONY:	build-info.h clean install
