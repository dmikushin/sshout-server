#ifndef _SSHOUT_CLIENT_H
#define _SSHOUT_CLIENT_H

extern int client_send_request_get_online_users(int);
extern int client_post_message(int, const struct local_message *);
extern int client_post_plain_text_message(int, const char *, const char *);
extern int client_get_local_socket_fd(void);

extern void client_cli_init_io(void);
extern void client_cli_do_local_packet(int);
extern void client_cli_do_stdin(int);
extern void client_cli_do_after_signal(void);

#endif
