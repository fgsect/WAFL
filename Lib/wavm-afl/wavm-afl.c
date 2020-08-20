// created by Keno Hassler, 2020

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include "WAVM/wavm-afl/wavm-afl.h"

static uint8_t dummy[MAP_SIZE];
uint8_t *afl_area_ptr = dummy;

__thread uint16_t afl_prev_loc[NGRAM_SIZE_MAX];

bool afl_is_persistent;

// prevent instrumenting more than once
bool afl_is_instrumented = false;

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
    afl_is_persistent = getenv(PERSIST_ENV_VAR);
    printf("finished afl_setup, persistent == %s\n", afl_is_persistent? "true" : "false");
}

void afl_forkserver() {
    static bool forkserver_installed = false;
    if (forkserver_installed) return;
    forkserver_installed = true;

    uint32_t flags = FS_OPT_ENABLED;
    if (MAP_SIZE <= FS_OPT_MAX_MAPSIZE) {
        flags |= (FS_OPT_MAPSIZE | FS_OPT_SET_MAPSIZE(MAP_SIZE));
    }

    /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */
    if (write(FORKSRV_FD + 1, &flags, 4) != 4) return;


    pid_t child_pid = -1;
    bool child_stopped = false;
    
    while(true) {

        int status = 0;

        /* Wait for parent by reading from the pipe. Abort if read fails. */
        if (read(FORKSRV_FD, &status, 4) != 4) exit(EXIT_FAILURE);

        /* If we stopped the child in persistent mode, but there was a race
           condition and afl-fuzz already issued SIGKILL, write off the old
           process. */
        if (child_stopped && status) {
            child_stopped = false;
            if (waitpid(child_pid, &status, 0) < 0) exit(EXIT_FAILURE);
        }

        if (!child_stopped) {
            /* Once woken up, create a clone of our process. */
            child_pid = fork();
            if (child_pid < 0) exit(EXIT_FAILURE);

            /* In child process: close fds, resume execution. */
            if (!child_pid) {
                //signal(SIGCHLD, SIG_DFL);

                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                return;
            }

        } else {

            /* Special handling for persistent mode: if the child is alive but
               currently stopped, simply restart it with SIGCONT. */
            kill(child_pid, SIGCONT);
            child_stopped = false;
            printf("child resumed\n");
        }
        
        /* In parent process: write PID to pipe, then wait for child. */
        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(EXIT_FAILURE);
        if (waitpid(child_pid, &status, afl_is_persistent ? WUNTRACED : 0) < 0)
            exit(EXIT_FAILURE);

        /* In persistent mode, the child stops itself with SIGSTOP to indicate
           a successful run. In this case, we want to wake it up without forking
           again. */
        if (WIFSTOPPED(status)) child_stopped = true;
        printf("___child stopped = %s ___\n", child_stopped? "true" : "false");
        
        /* Relay wait status to pipe, then loop back. */
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

int __afl_persistent_loop(unsigned int max_cnt) {
    static bool first_pass = true;
    static unsigned cycle_cnt;
    
    if (first_pass) {
        if (afl_is_persistent) {
            afl_area_ptr[0] = 1;
        }

        cycle_cnt = max_cnt;
        first_pass = false;
        return 1;
    }

    if (afl_is_persistent) {
        if (--cycle_cnt) {
            raise(SIGSTOP);
            afl_area_ptr[0] = 1;

            return 1;
        }
    }

    return 0;
}
