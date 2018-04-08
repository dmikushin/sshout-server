
#define SOCKET_NAME "socket"

#define USER_NAME_MAX_LENGTH 32
#define GLOBAL_NAME "GLOBAL"
#define USER_LIST_FILE ".ssh/authorized_keys"

#include <stdint.h>

// Local packets are used in UNIX domain sockets

#define LOCAL_PACKET_MAX_LENGTH (512 * 1024)

enum local_packet_type {
	SSHOUT_LOCAL_LOGIN,
	SSHOUT_LOCAL_POST_MESSAGE,
	SSHOUT_LOCAL_GET_ONLINE_USERS,
	SSHOUT_LOCAL_STATUS,
	SSHOUT_LOCAL_DISPATCH_MESSAGE,
	SSHOUT_LOCAL_ONLINE_USERS_INFO,
};

struct local_online_user {
	int id;
	char user_name[USER_NAME_MAX_LENGTH];
	char host_name[128];
};

struct local_online_users_info {
	int your_id;
	int count;
	struct local_online_user user[0];
};

enum local_msg_type {
	SSHOUT_MSG_PLAIN = 1,
	SSHOUT_MSG_RICH,
	SSHOUT_MSG_IMAGE
};

struct local_message {
	char msg_to[USER_NAME_MAX_LENGTH];
	enum local_msg_type msg_type;
	uint32_t msg_length;
	char msg[0];
};

struct sockaddr_un;

extern int client_mode(const struct sockaddr_un *, const char *);
extern int server_mode(const struct sockaddr_un *);
