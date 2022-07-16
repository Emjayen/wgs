/*
 * log.h
 * 
 */
#pragma once
#include "pce.h"





// Log levels
#define LOG_FATAL  0
#define LOG_ERROR  1
#define LOG_WARN   2
#define LOG_INFO   3
#define LOG_DEBUG  4

// Logging wrappers
#define LOG(_pFormat, ...) Log(LOG_INFO, _pFormat __VA_OPT__(,) __VA_ARGS__)
#define LERR(_pFormat, ...) Log(LOG_ERROR, _pFormat __VA_OPT__(,) __VA_ARGS__)
#define LFATAL(_pFormat, ...) Log(LOG_FATAL, _pFormat __VA_OPT__(,) __VA_ARGS__)
#define LWARN(_pFormat, ...) Log(LOG_WARN, _pFormat __VA_OPT__(,) __VA_ARGS__)
#define LDBG(_pFormat, ...) Log(LOG_DEBUG, _pFormat __VA_OPT__(,) __VA_ARGS__)



/*
 * Log
 *
 */
void Log(u8 Level, const char* pFormat, ...);



/*
 * LogStartup
 *
 */
bool LogStartup(const char* pFile);