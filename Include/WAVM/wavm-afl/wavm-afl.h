/* WAFL: fuzz WebAssembly binaries with AFL++ using WAVM

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Copyright 2021 Keno Hassler

   AFLplusplus macro definitions taken from the respective header files.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

	   https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

#ifndef WAVM_AFL_H
#define WAVM_AFL_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdbool.h>
#include <stdint.h>

/* from config.h */
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)
#define SHM_ENV_VAR "__AFL_SHM_ID"
#define FORKSRV_FD 198
#define PERSIST_ENV_VAR "__AFL_PERSISTENT"
#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"
#define MAX_FILE (1 * 1024 * 1024U)
#define DEFAULT_PERMISSION 0600

/* from types.h */
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_SHDMEM_FUZZ 0x01000000
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
#define FS_OPT_MAX_MAPSIZE ((0x00fffffe >> 1) + 1)
#define FS_OPT_GET_MAPSIZE(x) (((x & 0x00fffffe) >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))

/* from llvm-alternative-coverage.h */
#if(MAP_SIZE_POW2 <= 16)
typedef uint16_t PREV_LOC_T;
#elif(MAP_SIZE_POW2 <= 32)
typedef uint32_t PREV_LOC_T;
#else
typedef uint64_t PREV_LOC_T;
#endif
#define NGRAM_SIZE_MAX 16U

struct afl_options
{
	enum mode
	{
		none,    // don't instrument (useful when loading with --precompiled)
		classic, // traditional afl instrumentation
		cfg,     // control flow graph instrumentation (PCGUARD)
		native   // LLVM's trace_pc_guard
	} instr_mode;
	uint8_t ngram_size;
	bool ctx_enabled;
};

// prevent instrumenting more than once
extern bool afl_is_instrumented;

extern uint8_t* afl_area_ptr;
extern PREV_LOC_T afl_prev_loc[NGRAM_SIZE_MAX];
extern uint32_t afl_prev_ctx;

void afl_init();
bool afl_persistent_loop(uint32_t max_cnt);
struct afl_options afl_parse_env();
ssize_t afl_readv(int fd, const struct iovec* buffers, int numBuffers);

void trace_pc_guard(uint32_t* guard);
void trace_pc_guard_init(uint32_t* start, uint32_t* stop);
extern uint32_t trace_pc_guard_dummy;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // WAVM_AFL_H
