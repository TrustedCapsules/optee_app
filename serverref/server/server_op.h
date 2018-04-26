#ifndef SERVER_OP_H
#define SERVER_OP_H

struct capsule_entry* get_curr_capsule( uint32_t capsule_id );

int send_data( int fd, void *buf, size_t buf_len );
int recv_data( int fd, void *buf, size_t buf_len );

#endif /* SERVER_ENC_H */
