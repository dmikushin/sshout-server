
#define SOCKET_NAME "socket"

#define USER_NAME_MAX_LENGTH 32
#define GLOBAL_NAME "GLOBAL"
#define USER_LIST_FILE ".ssh/authorized_keys"
#define HOST_NAME_MAX_LENGTH 128

//#include <stdint.h>
#include <sys/types.h>

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

#define GET_PACKET_EOF -1
#define GET_PACKET_ERROR -2
#define GET_PACKET_SHORT_READ -3
#define GET_PACKET_TOO_LARGE -4
#define GET_PACKET_OUT_OF_MEMORY -5

// Doesn't need to use types from stdint.h in local packets
struct local_packet {
	size_t length;
	enum local_packet_type type;
	char data[0];
};

struct local_online_user {
	int id;
	char user_name[USER_NAME_MAX_LENGTH];
	char host_name[HOST_NAME_MAX_LENGTH];
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
	size_t msg_length;
	char msg[0];
};

struct sockaddr_un;

extern int get_local_packet(int, struct local_packet **);
extern int client_mode(const struct sockaddr_un *, const char *);
extern int server_mode(const struct sockaddr_un *);
