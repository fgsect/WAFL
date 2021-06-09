// created by Keno Hassler, 2020

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "WAVM/wavm-afl/wavm-afl.h"

// prevent instrumenting more than once
bool afl_is_instrumented = false;

static uint8_t afl_area_ptr_dummy[MAP_SIZE];
uint8_t* afl_area_ptr = afl_area_ptr_dummy;
PREV_LOC_T afl_prev_loc[NGRAM_SIZE_MAX];
uint32_t afl_prev_ctx;

static bool afl_sharedmem_fuzzing = true;
static uint8_t* afl_fuzz_ptr;
static uint32_t afl_fuzz_len_dummy;
static uint32_t* afl_fuzz_len = &afl_fuzz_len_dummy;

static bool is_persistent;

uint32_t trace_pc_guard_dummy;

void afl_map_shm()
{
	const char* shm_file_path = getenv(SHM_ENV_VAR);

	if(shm_file_path)
	{
		/* open the shared memory segment with read/write permissions */
		const int shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
		if(shm_fd == -1)
		{
			perror("afl_map_shm(): shm_open failed");
			exit(EXIT_FAILURE);
		}

		/* map the shared memory read/writeable (MAP_SIZE bytes) */
		afl_area_ptr = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
		if(afl_area_ptr == MAP_FAILED)
		{
			perror("afl_map_shm(): mmap failed");
			exit(EXIT_FAILURE);
		}

		close(shm_fd);
	}
}

void afl_map_shm_fuzz()
{
	const char* shm_file_path = getenv(SHM_FUZZ_ENV_VAR);

	if(shm_file_path)
	{
		/* open the shared memory segment with read-only permission */
		const int shm_fd = shm_open(shm_file_path, O_RDONLY, DEFAULT_PERMISSION);
		if(shm_fd == -1)
		{
			perror("afl_map_shm_fuzz(): shm_open failed");
			exit(EXIT_FAILURE);
		}

		/* map the shared memory readable (32-bit length + max. file size) */
		uint8_t* map = mmap(NULL, MAX_FILE + sizeof(uint32_t), PROT_READ, MAP_SHARED, shm_fd, 0);
		if(map == MAP_FAILED)
		{
			perror("afl_map_shm_fuzz(): mmap failed");
			exit(EXIT_FAILURE);
		}

		close(shm_fd);
		afl_fuzz_len = (uint32_t*)map;
		afl_fuzz_ptr = map + sizeof(uint32_t);
	}
	else
	{
		fprintf(stderr, "afl_map_shm_fuzz(): %s not set\n", SHM_FUZZ_ENV_VAR);
		exit(EXIT_FAILURE);
	}
}

void afl_start_forkserver()
{
	bool already_read_first = false;
	uint32_t flags = 0;
	if(MAP_SIZE <= FS_OPT_MAX_MAPSIZE) { flags |= (FS_OPT_MAPSIZE | FS_OPT_SET_MAPSIZE(MAP_SIZE)); }
	if(afl_sharedmem_fuzzing) { flags |= FS_OPT_SHDMEM_FUZZ; }
	if(flags) { flags |= FS_OPT_ENABLED; }

	/* Phone home and tell the parent that we're OK. If parent isn't there,
	   assume we're not running in forkserver mode and just execute program. */

	if(write(FORKSRV_FD + 1, &flags, 4) != 4)
	{
		afl_sharedmem_fuzzing = false;
		return;
	}

	if(afl_sharedmem_fuzzing)
	{
		flags = 0;
		if(read(FORKSRV_FD, &flags, 4) != 4) exit(EXIT_FAILURE);

		if((flags & (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) == (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ))
		{
			/* parent agreed to shmem fuzzing */
			afl_map_shm_fuzz();
		}
		else
		{
			afl_sharedmem_fuzzing = false;
			already_read_first = true;
		}
	}

	pid_t child_pid = -1;
	bool child_stopped = false;

	while(true)
	{
		int status = 0;

		/* Wait for parent by reading from the pipe. Abort if read fails. */

		if(already_read_first) { already_read_first = false; }
		else
		{
			if(read(FORKSRV_FD, &status, 4) != 4) exit(EXIT_FAILURE);
		}

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
	static bool init_done = false;

	if(!init_done)
	{
		is_persistent = getenv(PERSIST_ENV_VAR);
		afl_map_shm();
		afl_start_forkserver();
		init_done = true;
	}

	printf("finished afl_init, persistent mode %s\n", is_persistent ? "enabled" : "disabled");
}

bool afl_persistent_loop(uint32_t max_cnt)
{
	static bool first_pass = true;
	static uint32_t cycle_cnt;
	// printf("loop cycle cnt: %u\n", cycle_cnt);

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

/* if shmem fuzzing is active, put received input in a pipe to replace stdin */
void afl_fetch_input()
{
	if(afl_sharedmem_fuzzing)
	{
		int pipefd[2];
		if(pipe(pipefd) != 0)
		{
			perror("afl_fetch_input() failed creating pipe");
			exit(EXIT_FAILURE);
		}

		if(dup2(pipefd[0], STDIN_FILENO) != STDIN_FILENO)
		{
			perror("afl_fetch_input() failed replacing stdin");
			exit(EXIT_FAILURE);
		}
		close(pipefd[0]);

#ifdef __linux__
		/* resize pipe buffer to our needs (max. 1M possible) */
		if(fcntl(pipefd[1], F_SETPIPE_SZ, *afl_fuzz_len) == -1)
		{
			perror("afl_fetch_input() failed resizing pipe buffer");
			exit(EXIT_FAILURE);
		}

		/* avoid unnecessary copying, should benefit larger inputs */
		struct iovec iov = {afl_fuzz_ptr, *afl_fuzz_len};
		if(vmsplice(pipefd[1], &iov, 1, 0) != *afl_fuzz_len)
#else
		if(write(pipefd[1], afl_fuzz_ptr, *afl_fuzz_len) != *afl_fuzz_len)
#endif
		{
			perror("afl_fetch_input() failed writing to pipe");
			exit(EXIT_FAILURE);
		}
		close(pipefd[1]);
	}
}

/* callback for LLVM's trace_pc_guard instrumentation */
void trace_pc_guard(uint32_t* guard)
{
	if(*guard == 0)
	{
		/* The proper init function is never called, so all guards are 0 initially.
		   Thus, calculate a stable index for each guard from their address:
		   - subtract an offset pointer (stabilize against random mapping)
		   - divide by 4 (because guard is 32 bits)
		   - modulo MAP_SIZE. */

		const uintptr_t guard_id = (uintptr_t)&trace_pc_guard_dummy - (uintptr_t)guard;
		*guard = (guard_id >> 2) & (MAP_SIZE - 1);
	}

	afl_area_ptr[*guard]++;
}

/* callback stub for init */
void trace_pc_guard_init(uint32_t* start, uint32_t* stop)
{
	fprintf(stderr, "trace_pc_guard_init() not implemented\n");
	exit(EXIT_FAILURE);
}

/* parse the AFL_LLVM_INSTRUMENT environment variable into afl_options */
struct afl_options afl_parse_env()
{
	/* native pcguard mode, no NGRAM, no CTX set as default */
	struct afl_options opt = {native, 0, false};

	if(getenv("AFL_LLVM_INSTRUMENT"))
	{
		for(char* token = strtok(getenv("AFL_LLVM_INSTRUMENT"), ":,;"); token != NULL;
			token = strtok(NULL, ":,;"))
		{
			if(strncasecmp(token, "classic", strlen("classic")) == 0)
			{ opt.instr_mode = classic; }
			else if(strncasecmp(token, "cfg", strlen("cfg")) == 0)
			{ opt.instr_mode = cfg;	}
			else if(strncasecmp(token, "native", strlen("native")) == 0)
			{ opt.instr_mode = native; }
			else if(strncasecmp(token, "ctx", strlen("ctx")) == 0)
			{ opt.ctx_enabled = true; }
			else if(strncasecmp(token, "ngram-", strlen("ngram-")) == 0)
			{
				opt.ngram_size = strtoul(token + strlen("ngram-"), NULL, 10);
				if(opt.ngram_size < 2 || opt.ngram_size > NGRAM_SIZE_MAX)
				{
					fprintf(stderr, "error: NGRAM size must be between 2 and %u\n", NGRAM_SIZE_MAX);
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				fprintf(stderr, "warning: instrumentation option \"%s\" not recognized\n", token);
			}
		}
	}

	return opt;
}

/* DEBUG */
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

void afl_print_prevloc()
{
	printf("afl_prev_loc:");
	for(size_t i = 0; i < NGRAM_SIZE_MAX; i++) { printf(" %u", afl_prev_loc[i]); }
	printf("\n");
	printf("afl_prev_ctx: %u\n", afl_prev_ctx);
}
