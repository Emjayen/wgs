/*
 * log.cpp
 * 
 */
#include "wgs.h"
#include "log.h"




// Globals
static int hLog;



/*
 * LogStartup
 *
 */
bool LogStartup(const char* pFile)
{
	if((hLog = open(pFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU | S_IRUSR | S_IWUSR | S_IROTH)) < 0)
		return false;
	
	return true;
}


/*
 * Log
 *
 */
void Log(u8 Level, const char* pFormat, ...)
{
	static const char* LEVEL[] =
	{
		"FATAL",
		"ERROR",
		"WARN ",
		"INFO ",
		"DEBUG",
	};

	static char tmp[0x1000];
	char* pd = tmp;
	auto last_error = errno;

	// Get UTC time.
	timespec ts;
	clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	time_t time = { ts.tv_sec };
	tm* pTM = gmtime(&time);
	
	va_list va;
	va_start(va, pFormat);
	
	pd += snprintf(pd, sizeof(tmp), "\n%04u-%02u-%02u %02u:%02u:%02u | %s | ", 1900+pTM->tm_year, pTM->tm_mon, pTM->tm_mday, pTM->tm_hour, pTM->tm_min, pTM->tm_sec, LEVEL[Level]);
	pd += vsnprintf(pd, sizeof(tmp) - (pd - tmp), pFormat, va);
	
	if(Level <= LOG_ERROR)
		pd += snprintf(pd, sizeof(tmp) - (pd - tmp), " (err: %d)", last_error);
	
	write(hLog, tmp, (pd - tmp));
	printf("%s", tmp);
	
//#ifndef RELEASE
	fflush(stdout);
//#endif
	
	if(Level == LOG_FATAL)
		abort();
}