#ifndef CAPSULE_PROCESS_H
#define CAPSULE_PROCESS_H

int reply_change_policy( int fd, int id, AMessage *hdr, char* payload );
int reply_delete( int fd, int id, AMessage *hdr, char* payload );
int reply_get_state( int fd, int id, AMessage *hdr, char* payload );
int reply_report_locid( int fd, int id, AMessage *hdr, char* payload );

int reply_echo( int fd, int id, AMessage *hdr, char* payload );
void capsule_process( int fd );

#endif
