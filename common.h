
#define SOCKET_NAME "socket"

#define USER_NAME_MAX_LENGTH 32
#define GLOBAL_NAME "GLOBAL"
#define USER_LIST_FILE ".ssh/authorized_keys"

#include <stdint.h>

enum msg_type {
	MSG_PLAIN = 1,
	MSG_RICH,
	MSG_IMAGE
};

struct message {
	char msg_to[USER_NAME_MAX_LENGTH];
	enum msg_type msg_type;
	uint32_t msg_length;
	char msg[0];
};

struct sockaddr_un;

extern int client_mode(const struct sockaddr_un *, const char *);
extern int server_mode(const struct sockaddr_un *);
