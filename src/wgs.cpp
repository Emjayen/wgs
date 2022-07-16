/*
 * wgs.cpp
 * 
 */
#include "wgs.h"
#include "server.h"
#include <sys/random.h>





// Globals
int efd; /* Our epoll */
static int ifd; /* Interrupt timer. */
static TimerWheel<CFG_TW_SIZE, CFG_TW_GRANULARITY> tw;
static u32 cached_tick;


/*
 * Startup
 *
 */
bool Startup()
{
	if(!LogStartup(CFG_LOG_FILE))
		return false;
	
	// Ignore all signals except for faults.
	IgnoreSignalSet((SIGSEGV | SIGBUS) ^ ~0);
	
	// Initialize PRNG.
	u64 seed;
	getrandom(&seed, sizeof(seed), 0);
	xoro_seed(seed);
	
	// Setup epoll and the interrupt timer.
	if((efd = epoll_create(64)) < 0)
	{
		LERR("Failed to create epoll");
		return false;
	}
	
	itimerspec ts;
	ts.it_value.tv_sec = 0;
	ts.it_value.tv_nsec = 1;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 1000000 * CFG_INTR_INTERVAL;
	
	epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	
	if((ifd = timerfd_create(CLOCK_BOOTTIME, 0)) < 0 || timerfd_settime(ifd, 0, &ts, 0) < 0 || epoll_ctl(efd, EPOLL_CTL_ADD, ifd, &ev))
	{
		LERR("Failed to initialize interrupt timer.");
		return false;
	}


	return true;
}
	

/*
 * Entry
 * 
 */
int main()
{
	if(!Startup())
	{
		LERR("Startup failed");
		return -1;
	}
	
	if(!ServerStartup())
	{
		LERR("Server startup failed.");
		return -1;
	}
	
	LOG("Server running.");

	for(;;)
	{
		epoll_event ev[CFG_EPOLL_MAX_EVT];
		int count;
		
		if((count = epoll_wait(efd, ev, ARRAYSIZE(ev), -1)) <= 0)
			LWARN("Unexpected failure during epoll_wait()");
		
		else
		{
			bool intr_timer_expired = false;
			
			// Get coarse tick.
			cached_tick = GetTickMs();
			
			// Invoke registered handler routines associated with each fd.
			while(--count >= 0)
			{
				if(ev[count].data.ptr)
					(*((FDEVTCB*) ev[count].data.ptr))(ev[count].data.ptr, ev[count].events);
				
				else
					intr_timer_expired = true;
			}
			
			// We defer timer expiration processing till after other events.
			if(intr_timer_expired)
			{
				u64 accum;
				
				// Really wish we could avoid this syscall..
				if(read(ifd, &accum, sizeof(accum)) != sizeof(accum))
					LFATAL("Failed to read interrupt timer");
				
				tw.Advance(1);
			}
		}
		
	}
			
		
	
	
	
	return 1;
}



/*
 * SetTimer
 *
 */
void SetTimer(timer* t, u32 Due, u32 Period)
{
	tw.Set(t, Due, Period);
}


/*
 * GetTickCount()
 *
 */
u32 GetTickCount()
{
	return cached_tick;
}