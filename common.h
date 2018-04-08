
#define SOCKET_NAME "socket"

#define USER_NAME_MAX_LENGTH 32
#define GLOBAL_NAME "GLOBAL"
#define USER_LIST_FILE ".ssh/authorized_keys"

#include <stdint.h>

// Local packet types used in UNIX domain sockets
enum local_packet_type {
	SSHOUT_LOCAL_LOGIN,
	SSHOUT_LOCAL_POST_MESSAGE,
	SSHOUT_LOCAL_GET_ONLINE_USERS,
	SSHOUT_LOCAL_STATUS,
	SSHOUT_LOCAL_DISPATCH_MESSAGE,
};

enum msg_type {
	SSHOUT_MSG_PLAIN = 1,
	SSHOUT_MSG_RICH,
	SSHOUT_MSG_IMAGE
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
