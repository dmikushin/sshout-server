ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS += -Wall -O1
LIBS += -lreadline

OBJECTS = client.o client-cli.o local-packet.o main.o server.o

all:	sshoutcfg sshoutd

sshoutd:	$(OBJECTS)
	$(CC) $^ -o $@ $(LIBS)

clean:
	rm -f $(OBJECTS) sshoutd
