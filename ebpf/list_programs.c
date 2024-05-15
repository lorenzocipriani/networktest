#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

/*
Build:
clang -Wall -o list-programs list_programs.c $(pkg-config --cflags --libs libbpf)
*/
int main() {
    __u32 prog_id = 0;
    int err;

    while (1) {
        union bpf_attr attr_next_id = {
            .start_id = prog_id,
        };

        err = syscall(__NR_bpf, BPF_PROG_GET_NEXT_ID, &attr_next_id, sizeof(attr_next_id));
        if (err) {
            if (errno == ENOENT) {
                break; // No more programs
            } else {
                perror("BPF_PROG_GET_NEXT_ID");
                exit(EXIT_FAILURE);
            }
        }

        prog_id = attr_next_id.next_id;

        union bpf_attr attr_fd_by_id = {
            .prog_id = prog_id,
        };

        int prog_fd = syscall(__NR_bpf, BPF_PROG_GET_FD_BY_ID, &attr_fd_by_id, sizeof(attr_fd_by_id));
        if (prog_fd < 0) {
            perror("BPF_PROG_GET_FD_BY_ID");
            exit(EXIT_FAILURE);
        }

        struct bpf_prog_info info = {};
        __u32 info_len = sizeof(info);

        union bpf_attr attr_info = {
            .info.bpf_fd = prog_fd,
            .info.info = (uint64_t)&info,
            .info.info_len = info_len,
        };

        err = syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr_info, sizeof(attr_info));
        if (err) {
            perror("BPF_OBJ_GET_INFO_BY_FD");
            exit(EXIT_FAILURE);
        }

        printf("Program ID: %u\n", prog_id);
        printf("Program Type: %u\n", info.type);
        printf("Program Name: %s\n", info.name);

        close(prog_fd);
    }

    return 0;
}
