#define SSHOUT_VERSION "1.1.0"
#include "build-info.h"
#if !defined BUILD_DATE && defined __DATE__ && defined __TIME__
#define BUILD_DATE __DATE__ " " __TIME__
#endif
#if defined GIT_COMMIT && defined BUILD_DATE
#define SSHOUT_VERSION_STRING "SSHOUT " SSHOUT_VERSION " (commit " GIT_COMMIT ", built on " BUILD_DATE ")"
#elif defined GIT_COMMIT
#define SSHOUT_VERSION_STRING "SSHOUT " SSHOUT_VERSION " (commit " GIT_COMMIT ")"
#elif defined BUILD_DATE
#define SSHOUT_VERSION_STRING "SSHOUT " SSHOUT_VERSION " (built on " BUILD_DATE ")"
#else
#define SSHOUT_VERSION_STRING "SSHOUT " SSHOUT_VERSION
#endif
#define SOCKET_NAME "socket"
#define USER_NAME_MAX_LENGTH 32
#define GLOBAL_NAME "GLOBAL"
#define USER_LIST_FILE ".ssh/authorized_keys"
#define HOST_NAME_MAX_LENGTH 128
#define SSHOUT_MOTD_FILE "motd"
#define SSHOUT_USERS_PREFERENCES_DIR "users-preferences"

#include <stdint.h>
#include <sys/types.h>

// Local packets are used in UNIX domain sockets

#define LOCAL_PACKET_MAX_LENGTH (2 * 1024 * 1024)

enum local_packet_type {
	SSHOUT_LOCAL_LOGIN,
	SSHOUT_LOCAL_POST_MESSAGE,
	SSHOUT_LOCAL_GET_ONLINE_USERS,
	SSHOUT_LOCAL_USER_NOT_FOUND,
	SSHOUT_LOCAL_DISPATCH_MESSAGE,
	SSHOUT_LOCAL_ONLINE_USERS_INFO,
	SSHOUT_LOCAL_USER_ONLINE,
	SSHOUT_LOCAL_USER_OFFLINE,
};

#define GET_PACKET_EOF -1
#define GET_PACKET_ERROR -2
#define GET_PACKET_SHORT_READ -3
#define GET_PACKET_TOO_SMALL -4
#define GET_PACKET_TOO_LARGE -5
#define GET_PACKET_OUT_OF_MEMORY -6
#define GET_PACKET_INCOMPLETE -7

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
	char msg_from[USER_NAME_MAX_LENGTH];
	char msg_to[USER_NAME_MAX_LENGTH];
	enum local_msg_type msg_type;
	size_t msg_length;	// Only for array msg
	char msg[0];
};

struct private_buffer {
	char *buffer;
	size_t total_length;
	size_t read_length;
};

struct sockaddr_un;
struct sshout_api_packet;

extern int get_api_packet(int, struct sshout_api_packet **, uint32_t *, int);
extern int get_local_packet(int, struct local_packet **, struct private_buffer *);
extern int client_mode(const struct sockaddr_un *, const char *);
extern int server_mode(const struct sockaddr_un *);
