#ifndef __SENTINEL_COMMON_H__
#define __SENTINEL_COMMON_H__

#define TASK_COMM_LEN 16

struct accept_event {
    __u32 pid;
    __u32 fd;
    __u16 family;
    __u16 port;
    __u8 addr[16];
    char comm[TASK_COMM_LEN];
};

#endif
