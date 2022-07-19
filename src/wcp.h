/*
 * wcp.h
 * 
 */
#pragma once
#include "pce.h"





// General constants
#define WCP_MAGIC        0xF7 /* Signature for protocol messages in wcp_hdr */
#define WCP_MAX_NAME     16 /* Maximum player name length, including null-terminator */
#define WCP_MAX_GAME_NAME 20 /* This is not a hard limit; just what is likely to fit. */
#define WCP_MAX_CHAT_LEN 250

// Protocol message identifiers
#define WCP_JOIN         0x1E // C->S
#define WCP_PONG         0x46 // C->S
#define WCP_SUBMIT       0x26 // C->S
#define WCP_TURN_DONE    0x27 // C->S
#define WCP_LEAVE        0x21 // C->S
#define WCP_CHAT         0x28 // C->S
#define WCP_MAP_RESULT   0x42 // C->S
#define WCP_READY        0x23 // C->S
#define WCP_XFER_ACK     0x44 // C->S

#define WCP_PING         0x01 // S->C
#define WCP_MAP_QUERY    0x3D // S->C
#define WCP_REMOVE       0x07 // S->C
#define WCP_TURN         0x0C // S->C
#define WCP_TURN2        0x48 // S->C
#define WCP_PLAYER       0x06 // S->C
#define WCP_CHAT_EX      0x0F // S->C
#define WCP_STARTUP      0x04 // S->C
#define WCP_LOBBY        0x09 // S->C
#define WCP_COUNT_BEGIN  0x0A // S->C
#define WCP_COUNT_END    0x0B // S->C
#define WCP_READY_EX     0x08 // S->C
#define WCP_XFER_BEGIN   0x3F // S->C
#define WCP_XFER_CHUNK   0x43 // S->C

// Extended protocol message identifiers
#define WCP_TICK_EX      0x29

// Chat Control Types
#define WCP_CHAT_CTRL_MSG_LOBBY  0x10 /* Lobby chat message. */
#define WCP_CHAT_CTRL_SET_TEAM   0x11 /* Set team */
#define WCP_CHAT_CTRL_SET_COLOR  0x12 /* Set color */
#define WCP_CHAT_CTRL_SET_RACE   0x13 /* Set race */
#define WCP_CHAT_CTRL_SET_HCAP   0x14 /* Set handicap */
#define WCP_CHAT_CTRL_MSG_GAME   0x20 /* Game chat message. */

// Chat flags
#define WCP_CHAT_FLAG_GLOBAL   0x00000000
#define WCP_CHAT_FLAG_ALLIED   0x00000001
#define WCP_CHAT_FLAG_OBSERVER 0x00000002
#define WCP_CHAT_FLAG_PRIVATE  0x00000004
#define WCP_CHAT_FLAG_LOBBY    0x10000000

// States
#define WCP_STATE_OPEN      0
#define WCP_STATE_CLOSED    1
#define WCP_STATE_OCCUPIED  2

// Races
#define WCP_RACE_HUMAN      1
#define WCP_RACE_ORC        2
#define WCP_RACE_NIGHTELF   4
#define WCP_RACE_UNDEAD     8
#define WCP_RACE_UNDEFINED  64
#define WCP_RACE_OBSERVER   96

// AI
#define WCP_AI_EASY    0
#define WCP_AI_NORMAL  1
#define WCP_AI_HARD    2

// Controllers
#define WCP_CTRL_HUMAN  0
#define WCP_CTRL_AI     1

// Maximum slots (apparently 24 with 1.29)
#define WCP_MAX_SLOTS  12


#pragma pack(push, 1)

struct wcp_slot
{
	u8 pid;
	u8 transfer;
	u8 state;
	u8 ctrl;
	u8 team;
	u8 color;
	u8 race;
	u8 ai;
	u8 handicap;
};


struct wcp_cmd
{
	u8 pid;
	u16 len;
	byte data[];
};


struct wcp_hdr
{
	u8 magic;
	u8 mid;
	u16 len;
};


struct wcp_join : wcp_hdr
{
	u32 game_id; /* Game instance counter */
	u32 game_key; /* Entry key (local games) */
	u8 _1; /* Unknown */
	u16 port; /* ? */
	u32 peer_key; /* ? */
	char name[];
//  u32 _2;
//  u16 _3;
//  u32 _4;
};




struct wcp_ping : wcp_hdr
{
	u32 tick;
};


struct wcp_submit : wcp_hdr
{
	u32 crc;
	byte data[];
};


struct wcp_turn_done : wcp_hdr
{
	u8 unk;
	u32 state_crc;
};

struct wcp_leave : wcp_hdr
{
	u32 reason;
};


struct wcp_remove : wcp_hdr
{
	u8 pid;
	u32 reason;
};


struct wcp_turn : wcp_hdr
{
	union
	{
		struct
		{
			u16 period;
			u16 crc;
		};
		
		u32 crc_state;
	};
	
	byte input[];
};


struct wcp_startup : wcp_hdr
{
	byte data[]; /* slots + pid*/
};


struct wcp_map_result : wcp_hdr
{
	u32 _1;
	u8 result;
	u32 map_size;
};


struct wcp_ready : wcp_hdr
{
};


struct wcp_ready_ex : wcp_hdr
{
	u8 pid;
};

struct wcp_chat : wcp_hdr
{
	u8 recipient_count;
	byte data[];
};

struct wcp_chat_ex : wcp_hdr
{
	u8 count;
	u8 pid;
	u8 ctrl;
	
	union
	{
		struct
		{
			char text[0];
		} lobby;
		
		struct 
		{
			u32 flags;
			char text[0];
		} game;
	};
	
};


struct wcp_initxfer : wcp_hdr
{
	u32 unknown;
	u8 src_pid;
};


struct wcp_chunk : wcp_hdr
{
	u8 dst_pid;
	u8 src_pid;
	u32 unknown;
	u32 file_offset;
	u32 crc;
	byte file_data[];
};


struct wcp_ack : wcp_hdr
{
	u8 dst_pid;
	u8 src_pid;
	u32 unknown;
	u32 file_size;
};

struct wcp_obschat : wcp_hdr
{
	char msg[];
};


struct wcp_start_lag : wcp_hdr
{
	u8 count;
	u8 pid;
	u32 timestamp;
};

struct wcp_stop_lag : wcp_hdr
{
	u8 pid;
	u32 timestamp;
};


/*
 * WSP protocol
 * 
 */
#define WSP_MAGIC  0xB7

#define WSP_HELLO      1
#define WSP_ADD_GAME   2
#define WSP_REM_GAME   3

struct wsp_hdr
{
	u8 magic;
	u8 mid;
	u16 len;
};

struct wsp_hello : wsp_hdr
{
};

struct wsp_add_game : wsp_hdr
{
	u32 game_id;
    u32 game_key;
	u8 slots_total;
	u8 slots_used;
	u8 slots_players;
	u8 unused;
    u32 map_flags;
    u32 map_xor;
    u16 host_port;
    u32 host_addr;
	char ect[]; /* game name\0
	char ect[];  * host name\0
	char ect[];  * map path\0 
	char ect[];  */
    
};

struct wsp_rem_game : wsp_hdr
{
	u32 game_id;
};

#pragma pack(pop)