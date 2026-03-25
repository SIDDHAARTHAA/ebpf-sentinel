#ifndef __SENTINEL_COMMON_H__
#define __SENTINEL_COMMON_H__

#define TASK_COMM_LEN 16
#define HTTP_DATA_LEN 256

struct accept_event {
    __u32 pid;
    __u32 fd;
    __u16 family;
    __u16 port;
    __u8 addr[16];
    char comm[TASK_COMM_LEN];
};

struct connect_event {
    __u32 pid;
    __u32 fd;
    __u16 family;
    __u16 port;
    __u8 addr[16];
    char comm[TASK_COMM_LEN];
};

struct exec_event {
    __u32 pid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
};

struct sentinel_io_event {
    __u32 pid;
    __u32 fd;
    __u64 ts_ns;
    __u32 data_len;
    __u8 op;
    __u8 pad[3];
    char comm[TASK_COMM_LEN];
    __u8 data[HTTP_DATA_LEN];
};

#endif
