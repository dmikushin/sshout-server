ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS += -Wall -O1
LIBS += -lreadline

OBJECTS = client.o local-packet.o main.o server.o

sshoutd:	$(OBJECTS)
	$(CC) $^ -o $@ $(LIBS)

clean:
	rm -f $(OBJECTS) sshoutd
