/*
 * pce.h
 * 
 */
#pragma once
#include <stdint.h>
#include <string.h>




// Basic types
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef u8 byte;
typedef unsigned int uint;

// Compile-time array element count
#define ARRAYSIZE(_arr) (sizeof(_arr) / sizeof(*_arr))

// Assert
#define ASSERT(_exp) if(!(_exp)) { LFATAL("Assertion failure: " #_exp); }

// Helper macros
#define ctz __builtin_ctz
#define popcnt __builtin_popcount
#define memzero(_p, _bytes) memset(_p, 0, _bytes)
#define ffsbit __builtin_ffs

// Branch hints
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

// Iterating set bits
#define ITERATE_BITSET(_mask) for(u32 __ibsmask = (_mask), i; (i = ctz(__ibsmask)), __ibsmask; __ibsmask ^= (1<<i))

// Swap two integrals.
#define SWAP(_a, _b) do \
	{ \
		typeof(_a) _tmp = (_a); \
		(_a) = (_b); \
		(_b) = (_tmp); \
	} while(0); \
	
#define TEST() (1==1)