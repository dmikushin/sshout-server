#ifndef _SSHOUT_CLIENT_H
#define _SSHOUT_CLIENT_H

extern int client_send_request_get_online_users(int);
extern int client_post_message(int, const struct local_message *);
extern int client_post_plain_text_message(int, const char *, const char *);
extern int client_get_local_socket_fd(void);

struct client_frontend_actions {
	void (*init_io)(const char *);
	void (*do_local_packet)(int);
	void (*do_stdin)(int);
	void (*do_after_signal)(void);
	void (*do_tick)(void);
};

extern void client_cli_get_actions(struct client_frontend_actions *, int);
extern void client_api_get_actions(struct client_frontend_actions *);

#endif
