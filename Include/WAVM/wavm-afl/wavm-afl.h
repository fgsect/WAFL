// created by Keno Hassler, 2020

#ifndef WAVM_AFL_H
#define WAVM_AFL_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdint.h>
#include <stdbool.h>

/* to be removed - these should be included from afl/config.h */
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)
#define SHM_ENV_VAR "__AFL_SHM_ID"
#define FORKSRV_FD 198
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_MAX_MAPSIZE ((0x00fffffe >> 1) + 1)
#define FS_OPT_GET_MAPSIZE(x) (((x & 0x00fffffe) >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) \
  (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))
#define NGRAM_SIZE_MAX 16U

extern uint8_t *afl_area_ptr;

// prevent instrumenting more than once
extern bool afl_is_instrumented;

extern __thread uint16_t afl_prev_loc[NGRAM_SIZE_MAX];

void afl_setup();
void afl_forkserver();
void afl_print_map();

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // WAVM_AFL_H
