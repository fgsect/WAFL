// created by Keno Hassler, 2020

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#include "WAVM/wavm-afl/wavm-afl.h"

// prevent instrumenting more than once
bool afl_is_instrumented = false;

static uint8_t afl_area_ptr_dummy[MAP_SIZE];
uint8_t* afl_area_ptr = afl_area_ptr_dummy;
__thread PREV_LOC_T afl_prev_loc[NGRAM_SIZE_MAX];

static bool is_persistent;

void afl_map_shm()
{
	char* id_str = getenv(SHM_ENV_VAR);

	if(id_str)
	{
		uint32_t shm_id = atoi(id_str);
		afl_area_ptr = (uint8_t*)shmat(shm_id, NULL, 0);

		/* Whooooops. */

		if(!afl_area_ptr || afl_area_ptr == (void*)-1)
		{
			perror("afl_map_shm(): shmat failed.");
			exit(EXIT_FAILURE);
		}
	}
}

void afl_start_forkserver()
{
	static bool forkserver_installed = false;
	if(forkserver_installed) return;
	forkserver_installed = true;

	uint32_t flags = 0;
	if(MAP_SIZE <= FS_OPT_MAX_MAPSIZE) { flags |= (FS_OPT_MAPSIZE | FS_OPT_SET_MAPSIZE(MAP_SIZE)); }
	if(flags) { flags |= FS_OPT_ENABLED; }

	/* Phone home and tell the parent that we're OK. If parent isn't there,
	   assume we're not running in forkserver mode and just execute program. */

	if(write(FORKSRV_FD + 1, &flags, 4) != 4) return;

	pid_t child_pid = -1;
	bool child_stopped = false;

	while(true)
	{
		int status = 0;

		/* Wait for parent by reading from the pipe. Abort if read fails. */

		if(read(FORKSRV_FD, &status, 4) != 4) exit(EXIT_FAILURE);

		/* If we stopped the child in persistent mode, but there was a race
		   condition and afl-fuzz already issued SIGKILL, write off the old
		   process. */

		if(child_stopped && status)
		{
			child_stopped = false;
			if(waitpid(child_pid, &status, 0) < 0) exit(EXIT_FAILURE);
		}

		if(!child_stopped)
		{
			/* Once woken up, create a clone of our process. */

			child_pid = fork();
			if(child_pid < 0) exit(EXIT_FAILURE);

			/* In child process: close fds, resume execution. */

			if(!child_pid)
			{
				close(FORKSRV_FD);
				close(FORKSRV_FD + 1);
				return;
			}
		}
		else
		{
			/* Special handling for persistent mode: if the child is alive but
			   currently stopped, simply restart it with SIGCONT. */

			kill(child_pid, SIGCONT);
			child_stopped = false;
		}

		/* In parent process: write PID to pipe, then wait for child. */

		if(write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(EXIT_FAILURE);

		if(waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) exit(EXIT_FAILURE);

		/* In persistent mode, the child stops itself with SIGSTOP to indicate
		   a successful run. In this case, we want to wake it up without forking
		   again. */

		if(WIFSTOPPED(status)) child_stopped = true;

		/* Relay wait status to pipe, then loop back. */

		if(write(FORKSRV_FD + 1, &status, 4) != 4) exit(EXIT_FAILURE);
	}
}

void afl_init()
{
	is_persistent = getenv(PERSIST_ENV_VAR);

	afl_map_shm();
	afl_start_forkserver();

	printf("finished afl_init, persistent mode %s\n", is_persistent ? "enabled" : "disabled");
}

bool afl_persistent_loop(uint32_t max_cnt)
{
	static bool first_pass = true;
	static uint32_t cycle_cnt;

	if(first_pass)
	{
		/* No instrumented code runs before the loop, no need to clean up */
		if(is_persistent)
		{
			// memset(afl_area_ptr, 0, MAP_SIZE);
			afl_area_ptr[0] = 1;
			// memset(afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));
		}

		cycle_cnt = max_cnt;
		first_pass = false;

		return true;
	}

	if(is_persistent)
	{
		if(--cycle_cnt)
		{
			raise(SIGSTOP);

			afl_area_ptr[0] = 1;
			memset(afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));

			return true;
		}
		else
		{
			/* after the loop, there is no instrumented code either */
			// afl_area_ptr = afl_area_ptr_dummy;
		}
	}

	return false;
}

void afl_print_map()
{
	printf("AFL shared map state (only hit cells):\n");
	int cnt = 0;
	long sum = 0;
	for(unsigned i = 0; i < MAP_SIZE; i++)
	{
		if(afl_area_ptr[i] > 0)
		{
			printf("[%i]\t%i\n", i, afl_area_ptr[i]);
			cnt++;
			sum += afl_area_ptr[i];
		}
	}
	printf("=== TOTAL %i CELLS: %li ===\n", cnt, sum);
}