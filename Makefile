ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS += -Wall -O1
LIBS += -lreadline

OBJECTS = api-packet.o client.o client-api.o client-cli.o local-packet.o main.o server.o syncrw.o

all:	sshoutcfg sshoutd

sshoutd:	$(OBJECTS)
	$(CC) $^ -o $@ $(LIBS)

clean:
	rm -f $(OBJECTS) sshoutcfg sshoutd
