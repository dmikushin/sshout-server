ifeq ($(CC),cc)
CC := gcc
endif
CFLAGS = -Wall -O1

OBJECTS = client.o main.o server.o

sshoutd:	$(OBJECTS)
	$(CC) $^ -o $@

clean:
	rm -f $(OBJECTS) sshoutd
