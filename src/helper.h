/*
 * helper.h
 * 
 */
#pragma once
#include "wgs.h"
#include <cstddef>




/*
 * GetTickXX
 * 
 */
u64 GetTickNs();
u32 GetTickMs();

/*
 * IgnoreSignalSet
 *
 */
u64 IgnoreSignalSet(u64 sigset);


/*
 * xororand
 *
 */
void xoro_seed(u64 seed);
u64 xoro_rand();


/*
 * wcp_crc32
 *
 */
u32 wcp_crc32(void* pBuffer, u32 Length);


/*
 * memcpycrc
 * 
 */
u32 memcpycrc(u32 state, byte* __restrict__ dst, const byte* __restrict__ src, uint len);


// Forwards
struct timer;

// Timer callback signature
typedef void (*PFTIMERCB)(timer*, void* context);


// Timer state
struct timer
{
	timer* next;
	timer* prev;
	void* ctx;
	PFTIMERCB pfCb;
	u32 period;
	u32 rot;
};


// Freelist item
struct freelist
{
	freelist* next;
};

// Freelist functions
void* freelist_alloc(freelist* fl);
void freelist_free(freelist* fl, void* p);
void freelist_init(freelist* fl, void* pool, u32 element_size, u32 element_count);

// Doubly-linked list
struct list_node
{
	list_node* next;
	list_node* prev;
};


struct list
{
	list_node* head;
	list_node* tail;
	u32 count;
};

void list_append(list* pList, list_node* pNode);
void list_remove(list* pList, list_node* pNode);

#define LIST_ADD(_list, _node) list_append(&(_list), ((list_node*) _node))
#define LIST_DEL(_list, _node) list_remove(&(_list), ((list_node*) _node))

// Timer-wheel
template<u32 Size, u32 Granularity> class TimerWheel
{
private:
	timer* wheel[Size];
	u32 cur_tick;
	u32 cur_rot;


public:
	/*
	 * Set
	 *   Arms a timer.
	 *
	 */
	void Set(timer* pTimer, u32 Due, u32 Period)
	{
		// Remove timer from current slot if any.
		if(pTimer->prev)
		{
			pTimer->prev->next = pTimer->next;

			if(pTimer->next)
				pTimer->next->prev = pTimer->prev;
		}
		
		// Due and period not being supplied indicates a disarming of the timer.
		if(!Due && !Period)
		{
			pTimer->next = NULL;
			pTimer->prev = NULL;
			
			return;
		}

		// A zero due time indicates to schedule at next period.
		if(!Due)
			Due = Period;

		// Compute wheel slot, rotation and period ticks.
		u32 slot = (cur_tick + (Due / Granularity)) % Size;
		pTimer->rot = cur_rot + ((cur_tick + (Due / Granularity)) / Size);
		pTimer->period = Period;

		// Insert timer at scheduled slot in wheel at the head of the list.
		if(wheel[slot])
			wheel[slot]->prev = pTimer;

		pTimer->next = wheel[slot];
		pTimer->prev = (timer*) &wheel[slot];

		wheel[slot] = pTimer;
	}


	/*
	 * QueryNextExpire
	 *   Determines the period of time until the next scheduled timer expiration.
	 *
	 */
	u32 QueryNextExpire(u32 Limit)
	{
		u32 period = 0;

		Limit /= Granularity;

		for(u32 tick = cur_tick; !wheel[tick++] && period < Limit; period++)
		{
			if(tick >= Size)
				tick = 0;
		}

		return period * Granularity;
	}

	
	/*
	 * Advance
	 *   Advance timer by time.
	 *
	 */
	void Advance(u32 DeltaTicks)
	{
		while(DeltaTicks)
		{
			if((cur_tick += 1) >= Size)
			{
				cur_tick = 0;
				cur_rot++;
			}

			for(timer* p = wheel[cur_tick], *pn; p; p = pn)
			{
				pn = p->next;

				if(p->rot == cur_rot)
				{
					// Re-arm timer 
					if(p->period)
						Set(p, 0, p->period);

					p->pfCb(p, p->ctx);
				}
			}

			DeltaTicks--;
		}
	}
};



// Object pool
template <typename t, uint Size> struct Pool
{
	t* next;
	t obj[Size];
	
	
	t* Allocate()
	{
		t* p = next;
		
		if(p)
			next = *((t**) p);
		
		return p;
	}
	
	void Free(t* p)
	{
		*((t**) p) = next;
		next = p;
	}
	
	void Initialize()
	{
		for(int i = Size-1; i >= 0; i--)
			Free(&obj[i]);
	}
	
	t& operator [](int i)
	{
		return obj[i];
	}
	
	uint operator -(t* p)
	{
		return p-obj;
	}
};