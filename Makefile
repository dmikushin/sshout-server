ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS += -Wall -Wno-switch -Wno-char-subscripts -O1
#LIBS += 

SSHOUTCFG_OBJCTS = base64.o sshoutcfg.o syncrw.o
SSHOUTD_OBJECTS = api-packet.o client.o client-api.o client-cli.o client-irc.o local-packet.o main.o server.o syncrw.o
SSHOUTCFG_LIBS = -lmhash
SSHOUTD_LIBS = -lreadline

all:	sshoutcfg sshoutd

sshoutcfg:	$(SSHOUTCFG_OBJCTS)
	$(CC) $^ -o $@ $(SSHOUTCFG_LIBS) $(LIBS)

sshoutd:	$(SSHOUTD_OBJECTS)
	$(CC) $^ -o $@ $(SSHOUTD_LIBS) $(LIBS)

clean:
	rm -f $(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS) sshoutcfg sshoutd
