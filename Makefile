ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS += -Wall -O1
LIBS += -lreadline

SSHOUTCFG_OBJCTS = sshoutcfg.o syncrw.o
SSHOUTD_OBJECTS = api-packet.o client.o client-api.o client-cli.o local-packet.o main.o server.o syncrw.o

all:	sshoutcfg sshoutd

sshoutcfg:	$(SSHOUTCFG_OBJCTS)
	$(CC) $^ -o $@ $(LIBS)

sshoutd:	$(SSHOUTD_OBJECTS)
	$(CC) $^ -o $@ $(LIBS)

clean:
	rm -f $(SSHOUTCFG_OBJCTS) $(SSHOUTD_OBJECTS) sshoutcfg sshoutd
