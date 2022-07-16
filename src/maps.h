/*
 * maps.h
 * 
 */
#pragma once
#include "wcp.h"



struct war3_map
{
	const char* game_name;
	
	u32 map_flags;
	u32 max_players; /* Excludes observers. */
	u32 slot_count; /* Total slots. */
	wcp_slot slots[WCP_MAX_SLOTS];
	
	byte map_sha[20];
	u32 map_crc;
	u32 map_xor;
	u32 map_file_sz;
	const char* file_path;
};


static war3_map Maps[] =
{
	{
		/* game_name      */ "DotA",
		/* map_flags      */ 0x67802,
		/* max_players    */ 10,
		/* slot_count     */ 12,
		
		{
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 0, 1, WCP_RACE_NIGHTELF, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 0, 2, WCP_RACE_NIGHTELF, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 0, 3, WCP_RACE_NIGHTELF, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 0, 4, WCP_RACE_NIGHTELF, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 0, 5, WCP_RACE_NIGHTELF, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 1, 7, WCP_RACE_UNDEAD, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 1, 8, WCP_RACE_UNDEAD, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 1, 9, WCP_RACE_UNDEAD, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 1, 10, WCP_RACE_UNDEAD, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 1, 11, WCP_RACE_UNDEAD, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 0x18, 0x18, WCP_RACE_OBSERVER, WCP_AI_NORMAL, 100 },
			{ 0, 100, WCP_STATE_OPEN, WCP_CTRL_HUMAN, 0x18, 0x18, WCP_RACE_OBSERVER, WCP_AI_NORMAL, 100 },
		},
			
		/* map_sha     */ { 0xED, 0xEB, 0xB7, 0x7D, 0xB5, 0x06, 0x95, 0xAD, 0xB6, 0x4E, 0x69, 0x86, 0xC7, 0x55, 0xBB, 0xD7, 0x3E, 0x68, 0x17, 0x98 },
		/* map_crc     */ 0x50801E5E,
		/* map_xor     */ 0x51E3422F,
		/* map_file_sz */ 7849077,
		/* file_path   */ "Maps/Download/DotA v6.83dAI PMV 1.42 EN.w3x"
	},
};