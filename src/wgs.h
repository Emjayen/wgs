/*
 * wgs.h
 * 
 */
#pragma once
#include "pce.h"
#include "log.h"
#include "helper.h"
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cstddef>
#include <sys/mman.h>


// File descriptor event handler signature; must be first member of epoll userdata struct.
typedef void (*FDEVTCB)(void*, u32);

// Exposed epoll
extern int efd;

// Timers
struct timer;
void SetTimer(timer* t, u32 Due, u32 Period);


/*
 * GetTickCount()
 *
 */
u32 GetTickCount();


// Config
#define CFG_LOG_FILE         "wgs.txt"
#define CFG_INTR_INTERVAL    16  /* Interrupt interval that serves as the granularity for all timers. */
#define CFG_TW_SIZE          128 /* Timer-wheel size; performance only. */
#define CFG_TW_GRANULARITY   CFG_INTR_INTERVAL 
#define CFG_EPOLL_MAX_EVT    16 /* Controls the batching limit of epoll_wait() */
#define CFG_TURN_PERIOD      48 /* Default turn period, in msec. */
#define CFG_MAX_GAMES        8 /* Maximum number of concurrent game instances. */
#define CFG_MAX_PLAYERS      (CFG_MAX_GAMES * 16) /* Maximum number of players in total. */
#define CFG_MAX_TURNS        324000 /* About 3 hours @ 32ms turns */
#define CFG_MAX_GAME_STREAM  0x1000000 /* (16MB) Governs the size of the game input stream; this needs to accomodate all input, from all players, for the entire session. */
#define CFG_GAME_PORT           6112 /* Port for game (WCP). */
#define CFG_KEEPALIVE_IDLE      20 /* Threshold for TCP keep-alive engaging, in seconds */
#define CFG_KEEPALIVE_COUNT     3  /* Number of TCP keep-alive probes before timing out, in seconds */
#define CFG_KEEPALIVE_INTERVAL  12 /* Interval between keep-alive probes, in seconds */
#define CFG_XMIT_TIMEOUT        ((CFG_KEEPALIVE_IDLE + (CFG_KEEPALIVE_COUNT * CFG_KEEPALIVE_INTERVAL)) / 2) * 1000
#define CFG_DEFER_ACPT_TIME     4
#define CFG_TCP_QUEUE_DEPTH     128
#define CFG_PLAYER_SNDBUF_SZ    0x1000 /* Player userland send buffer size. */
#define CFG_MAX_RX_WCP_MSG_SZ   2048 /* Maximum size of a C->S WCP message. */
#define CFG_PLAYER_RXMB_SZ      (CFG_MAX_RX_WCP_MSG_SZ*2)
#define CFG_PING_INTERVAL       6000 /* Ping interval, in msec. */
#define CFG_TURN_CLAMP          250 /* Clamps the maximum turn period; excess time will just be eaten. */
#define CFG_STALL_THRESHOLD     3500 /* Threshold at which a player stalls, in [simulation] msec. */