
//#define SOCKET_PATH "/var/lib/talk/socket"

#define USER_NAME_MAX_LENGTH 32
#define GLOBAL_NAME "GLOBAL"

enum msg_type {
	MSG_PLAIN = 1,
	MSG_RICH,
	MSG_IMAGE
};

struct message {
	char msg_to[USER_NAME_MAX_LENGTH];
	enum msg_type msg_type;
	char msg[0];
};

extern int client_mode(const char *);
