ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS += -Wall -Wno-switch -O1
#LIBS += 

SSHOUTCFG_OBJCTS = sshoutcfg.o syncrw.o
SSHOUTD_OBJECTS = api-packet.o client.o client-api.o client-cli.o client-irc.o local-packet.o main.o server.o syncrw.o
SSHOUTD_LIBS = -lreadline

all:	sshoutcfg sshoutd

sshoutcfg:	$(SSHOUTCFG_OBJCTS)
	$(CC) $^ -o $@ $(LIBS)

sshoutd:	$(SSHOUTD_OBJECTS)
	$(CC) $^ -o $@ $(SSHOUTD_LIBS) $(LIBS)

clean:
	rm -f $(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS) sshoutcfg sshoutd
