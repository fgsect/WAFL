// created by Keno Hassler, 2020

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include "WAVM/wavm-afl/wavm-afl.h"

static uint8_t dummy[MAP_SIZE];
uint8_t *afl_area_ptr = dummy;

// prevent instrumenting more than once
bool afl_is_instrumented = false;

__thread uint16_t afl_prev_loc[NGRAM_SIZE_MAX];

void afl_setup() {
	// set up the shared memory region
    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str) {
        int shm_id = atoi(id_str);
        afl_area_ptr = (uint8_t*) shmat(shm_id, NULL, 0);

        if ((uint8_t*) -1 == afl_area_ptr) {
            perror("afl_setup(): memory mapping failed.");
            exit(EXIT_FAILURE);
        }
    }
    printf("finished afl_setup\n");
}

void afl_forkserver() {
    static bool forkserver_installed = false;
	if (forkserver_installed) return;
    forkserver_installed = true;

    // say hello to afl
    uint8_t msg[4] = {0};
    if (MAP_SIZE <= FS_OPT_MAX_MAPSIZE) {
        int map_size = (FS_OPT_ENABLED | FS_OPT_MAPSIZE | FS_OPT_SET_MAPSIZE(MAP_SIZE));
        memcpy(msg, &map_size, 4);
    }
    printf("afl_forkserver(): initialised\n");
    if (write(FORKSRV_FD + 1, msg, 4) != 4) return;
    printf("afl_forkserver(): entering main loop\n");
    while(true) {
        // wait for afl (ignoring the answer for now)
        if (read(FORKSRV_FD, msg, 4) != 4) exit(EXIT_FAILURE);

        pid_t child_pid = fork();
        if (child_pid < 0) exit(EXIT_FAILURE);

        if (!child_pid) {
            // child process: start actual execution
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            return;
        }

        // parent process: tell afl about the child
        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(EXIT_FAILURE);

        // wait for the child, relay exit status to afl
        int status;
        if (waitpid(child_pid, &status, 0) < 0) exit(EXIT_FAILURE);
        if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(EXIT_FAILURE);
    }
}

void afl_print_map() {
    printf("AFL shared map state (only hit cells):\n");
    for (unsigned i = 0; i < MAP_SIZE; i++) {
        if (afl_area_ptr[i] > 0) {
            printf("[%i]\t%i\n", i, afl_area_ptr[i]);
        }
    }
    printf("--------------------------------------\n");
}