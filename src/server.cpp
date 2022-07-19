/*
 * server.cpp
 *
 */
#include "server.h"
#include "maps.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>



// Forwards
struct Player;
struct Game;

// Prototypes
Game* CreateGame(war3_map* pMap, const char* pName, const char* pHost);
Player* CreatePlayer(int s, const char* pName, u32 Addr);
void OnGameStateChange(Game* pGame, war3_map* pMap, u8 Operation);
bool FlushGameStateChanges(int s);

// Denotes an invalid slot index or slot property.
#define SLOT_NULL 0xFF
#define PID_NULL  0xFF

// PID -> pmask
#define PMASK(_pid) (((u32) 1) << (_pid))

// Game states
#define GAME_STATE_LOBBY  1
#define GAME_STATE_LOAD   2
#define GAME_STATE_RUN    3

// Protocol serialization helpers
#define WCP_HDR(_hdr) ((wcp_hdr*) (_hdr))
#define WRITE_WCP_HDR(_mid) ((wcp_hdr*) p)->magic = WCP_MAGIC; ((wcp_hdr*) p)->mid = _mid; pb = p; p += sizeof(wcp_hdr);
#define WRITE_WCP_LEN() WCP_HDR(pb)->len = (p-pb);
#define WRITE_BYTE(val) *((byte*) p) = val; p += 1;
#define WRITE_WORD(val) *((u16*) p) = val; p += 2;
#define WRITE_DWORD(val) *((u32*) p) = val; p += 4;
#define WRITE_VOID(val, _bytes) memcpy(p, val, _bytes); p += _bytes;
#define WRITE_STRING(val) strcpy((char*) p, val); p += strlen((char*) val)+1;
#define WRITE_STRING_CONST(_format, ...) p += sprintf((char*) p, _format, ##__VA_ARGS__)+1;
#define WRITE_NULL(_bytes) memzero(p, _bytes); p += _bytes;

// Adjusting internal to WCP PID
#define WCP_PID(_pid) (_pid + 1)

// Context logging
#define PLOG(_pFormat, ...) LOG("[%s] " _pFormat, this->name, ##__VA_ARGS__)

// Generation of initial game-state seed
#define GenerateGameSeed() 0xDEADBEEF


// Player
struct Player
{
	FDEVTCB pfsockevt; /* Must always be first; callback invoked when event on our socket 's' */
	int s; /* Socket */
	
	Game* g; /* Current game the player is in. */
	
	byte* rxm; /* Receive message buffer. */
	u32 rxm_len; /* Length of receive-message buffer. */
	
	byte* psb; /* Queued send buffer. */
	u32 psb_len; /* Current length of the send buffer. */
	
	u32 addr; /* Network (IP) address */
	char name[WCP_MAX_NAME]; /* Player name */
	
	u8 sid; /* Current slot */
	u8 pid; /* Player ID */
	
	u32 sim_time; /* Current amount of time simulated */
	u32 turn_ack; /* Last completed turn. */
	u32 turn_nxt; /* The next turn to be sent. */
	byte* ins_head_ptr; /* Game input stream head. */
	
	// Callback for socket events.
	void OnSocketEvent(u32 events);
	
	// Message handlers; return false on failure -> destroy.
	bool OnSubmit(wcp_submit* pMsg);
	bool OnTurnDone(wcp_turn_done* pMsg);
	bool OnPong(wcp_ping* pMsg);
	bool OnLeave(wcp_leave* pMsg);
	bool OnChat(wcp_chat* pMsg);
	bool OnMapResult(wcp_map_result* pMsg);
	bool OnReady(wcp_ready* pMsg);
	
	// Process chat command.
	void ProcessChatCommand(const char* pText);
	
	// Write to send queue.
	void Send(void* pData, u32 Len);
	
	// Compute the amount of game stream for this player to consume.
	uint ComputeStreamConsume();
	
	// Helpers
	bool IsObserver();
	bool HasStalled();
	
	// Start game for the player (client only)
	void StartGame();
	
	// Destroy player object and free.
	void Destroy();
};


// Turn information
struct turn_info
{
	u32 ins_off; /* Offset into the game-stream where this turn begins (WCP_TURN or WCP_TURN2) */
	u32 ins_len; /* Total length of the turn; this will include WCP_TURN and optionally WCP_TURN2 and any appended WCP_REMOVE. */
	u32 state_csum; /* The player concensus of the game-state for this turn. */
	u32 pmask_done; /* Players who have completed this turn. */
	u16 period; /* The time window of this turn, in msec (copy of WCP_TURN->period) */
};

// Game
struct Game
{
	Game* next;
	Game* prev;
	
	timer tmr; /* Timer used for turn scheduling. */
	
	u8 dirty_lobby_state : 1; /* Lobby state is dirty and needs flush. */
	u8 idle_timeout : 1; /* Set once the game-timeout has begun. */
	
	byte* ins_buf; /* Input stream buffer. */
	byte* ins_head; /* Current head of the stream. */
	
	union 
	{
		wcp_turn* ins_turn; /* Current turn being written out. */
		wcp_remove* ins_rm; 
		byte* ins_turn_ptr; /* Simplifies pointer arithmetic. */
	};
	
	turn_info* tinf; /* Turn information. */
	
	
	u8 state; /* Current game session state (GAME_STATE_*) */
	u8 turn_period; /* Turn length, in msec. */
	u8 virtual_obs_pid; /* Virtualized PID used for observers (client perspective only) */
	u32 turn; /* Current turn counter. */
	u32 sim_time; /* Current simulation time, in msec. */
	u32 seed; /* Game seed. */
	u32 last_ping; /* Last sent ping. */
	u64 t_accum; /* Time accumulator. */
	u64 t_last; /* Last time sample/turn. */
	
	u32 pmask_valid_players; /* PIDs available for general players. */
	u32 pmask_players; /* Currently occupied players. This excludes observers. */
	u32 pmask_dummy_players; /* Dummy players in observer slots (if any) */
	u32 pmask_clients; /* Currently occupied players and observers. */
	u32 pmask_connected; /* Players who are connected. */
	u32 pmask_xferred; /* Players who have completed their map transfer. */
	u32 pmask_loaded; /* Players who have finished loading the game. */
	u32 pmask_stall; /* Players currently stalling. */
	u32 pmask_remove; /* Players pending to be removed. */
	
	Player* players[32]; /* Members of the game session; includes observers. */
	
	wcp_slot slots[WCP_MAX_SLOTS]; /* Game "slots" */
	
	war3_map* map;
	char host_name[WCP_MAX_NAME];
	char game_name[WCP_MAX_GAME_NAME];
	char pname[WCP_MAX_SLOTS][WCP_MAX_NAME];
	
	
	// Destroy game.
	void Destroy();
	
	// Timer expiration.
	void OnTimerExpire();
	
	// Get player by PID
	Player* GetPlayer(u8 pid) { return players[pid]; }
	
	// Send data to set of players.
	void Send(u32 pmask, void* pData, u32 Len);
	
	// Send updated lobby state.
	void FlushLobbyState(u32 pmask);
	
	// Insert new turn input/commands to current turn.
	void TurnAppend(u8 src_pid, void* pData, u16 Len);
	
	// Send chat to clients.
	void Chat(u32 pmask, Player* src, u32 flags, const char* pFormat, ...);
	
	// Add (join) new player to game.
	bool AddPlayer(Player* pPlayer);
	
	// Add (join) new observer to game.
	bool AddObserver(Player* pPlayer);
	
	// Remove player from game.
	void RemovePlayer(Player* pPlayer);
	
	// Game timing out; begin if not started; cancel if criteria met (client joins)
	void TimeoutBegin();
	void TimeoutCancel();
	
	// Move player slot.
	bool MovePlayer(Player* pPlayer, u8 dst_sid, u8 match_state, u8 match_ctrl, u8 match_team);
	
	// Begin the game.
	bool Start();
};



// Globals
static int hListen; /* Game server socket. */
static Pool<Game, CFG_MAX_GAMES> Games;
static Pool<Player, CFG_MAX_PLAYERS> Players;
static list lstGames; /* All games */
static byte Scratch[0x1000];
static int hUsers[CFG_MAX_USERS];
static uint UsersLen;
static byte UserBuffer[0x1000];
static uint UserBufferLen;




/*
 * OnGameListenEvt
 * 
 */
void OnGameListenEvt(void*, u32 events)
{
	int s;
	sockaddr_in sa;
	socklen_t sa_len;
	int r;
	Player* pPlayer;
	
	
	union
	{
		wsp_hello hello_msg;
		wcp_join join_msg;
		byte _pad[64];
	};

	if((s = accept4(hListen, (sockaddr*) &sa, &(sa_len=sizeof(sa)), SOCK_NONBLOCK)) < 0)
	{
		LERR("Failure accept()ing new player connection.");
		return;
	}
	
	if((r = recv(s, &join_msg, sizeof(_pad), 0)) < sizeof(wcp_hdr) || r != join_msg.len)
	{
		LERR("Failure receiving initial join message.");
		goto FAIL;
	}
	
	// WSP-protocol?
	if(hello_msg.magic == WSP_MAGIC)
	{
		LOG("Accepted new user connection (s%u); addr:%s", s, inet_ntoa(sa.sin_addr));
		
		if(UsersLen >= ARRAYSIZE(hUsers))
		{
			LERR("Unable to accept new user; exceeded limit.");
			goto FAIL;
		}
		
		// Send map list.
		for(uint i = 0; i < ARRAYSIZE(Maps); i++)
			OnGameStateChange(NULL, &Maps[i], WSP_ADD_GAME);
		
		// Followed by the actual game-list.
		for(Game* p = (Game*) lstGames.head; p; p = p->next)
			OnGameStateChange(p, NULL, WSP_ADD_GAME);
			
		// Flush to new user.
		if(FlushGameStateChanges(s))
			hUsers[UsersLen++] = s;
		
		else
		{
			LERR("Failed to flush initial game list state");
			goto FAIL;
		}
	}
	
	// WCP-protocol
	else if(join_msg.magic == WCP_MAGIC)
	{
		LOG("Accepted new game connection; addr:%s name:%s game_id:%u game_token:0x%X ", inet_ntoa(sa.sin_addr), join_msg.name, join_msg.game_id, join_msg.game_key);
	
	
		// Create a new player from this new connection.
		if (!(pPlayer = CreatePlayer(s, join_msg.name, sa.sin_addr.s_addr)))
		{
			LOG("Rejected new player; failed to create object.");
			goto FAIL;
		}
		
		// We get a 1-based index; adjust it.
		auto game_id = join_msg.game_id - 1;
		
		// This will be the game we join, whether it's created or we're joining an existing.
		Game* pGame = NULL;
	
		// Creating a new game?
		if(game_id < ARRAYSIZE(Maps))
		{
			static u32 match_id; // Monotonically incrementing match ID for all games.
			char new_game_name[32];
			war3_map* pMap = &Maps[game_id];
			
			snprintf(new_game_name, WCP_MAX_GAME_NAME, "%s Match #%u", pMap->game_name, ++match_id);
			
			// Create game and select it as target.
			pGame = CreateGame(pMap, new_game_name, pPlayer->name);
		}
		
		// Joining an existing game.
		else
		{
			// Bring within range of game pool.
			game_id -= ARRAYSIZE(Maps);
			
			// Verify array bounds to Game pool at a minimum.
			if(game_id >= CFG_MAX_GAMES)
			{
				LERR("Player attempted to join invalid game index: %u", game_id);
				goto FAIL;
			}
			
			// Set selected game as target.
			pGame = &Games[game_id];
		}
		
		LOG("Player %s joining game %s", pPlayer->name, pGame->game_name);
		
		// We may still fail to enter.
		if(!pGame->AddPlayer(pPlayer))
		{
			LOG("Failed to join as player.");
			
			if(!pGame->AddObserver(pPlayer))
			{
				LOG("Failed to join as observer");
				goto FAIL;
			}
		}
	}
	
	// ??
	else
	{
		LERR("Received unexpected protocol magic: 0x%X", join_msg.magic);
		goto FAIL;
	}
	
	// success
	return;
	
	
FAIL:
	close(s);
}



// Fluff
void OnGameTimerExpire(timer*, void* p)
{
	((Game*) p)->OnTimerExpire();
}


/*
 * CreateGame
 *
 */
Game* CreateGame(war3_map* pMap, const char* pName, const char* pHost)
{
	Game* pGame;
	
	
	if(!(pGame = Games.Allocate()))
	{
		LERR("Failed to allocate new game object.");
		return NULL;
	}
	
	memzero(pGame, sizeof(*pGame));
	
	if(!(pGame->ins_buf = (byte*) mmap(NULL, CFG_MAX_GAME_STREAM, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)))
	{
		LERR("Failed to allocate input stream buffer.");
		return NULL;
	}
	
	if(!(pGame->tinf = (turn_info*) mmap(NULL, CFG_MAX_TURNS * sizeof(turn_info), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)))
	{
		LERR("Failed to allocate turn info.");
		goto FAIL;
	}
	
	pGame->state = GAME_STATE_LOBBY;
	pGame->pmask_valid_players = (((u32) 1) << pMap->max_players) - 1;
	pGame->pmask_dummy_players = ((((u32) 1) << (pMap->slot_count - pMap->max_players))-1) << pMap->max_players;
	pGame->virtual_obs_pid = ffsbit(pGame->pmask_dummy_players);
	pGame->turn_period = CFG_TURN_PERIOD;
	pGame->seed = (u32) GenerateGameSeed();
	pGame->map = pMap;
	memcpy(pGame->slots, pGame->map->slots, pGame->map->slot_count * sizeof(wcp_slot));
	strncpy(pGame->game_name, pName, sizeof(pGame->game_name));
	strncpy(pGame->host_name, pHost, sizeof(pGame->host_name));
	
	// Setup dummy players.
	for(u8 i = pMap->max_players; i < pMap->slot_count; i++)
	{
		wcp_slot& slot = pGame->slots[i];
		
		slot.pid = WCP_PID(i);
		slot.ctrl = WCP_CTRL_HUMAN;
		slot.state = WCP_STATE_OCCUPIED;
	}
	
	// Stream buffer variables.
	pGame->ins_head = pGame->ins_buf;
	pGame->ins_turn_ptr = pGame->ins_buf;
	
	// Initialize timer callback and context.
	pGame->tmr.pfCb = &OnGameTimerExpire;
	pGame->tmr.ctx = pGame;

	// Add to the global game list.
	LIST_ADD(lstGames, pGame);
	
	LOG("*** Created new game; idx=%u, name=%s host=%s map=%s", Games-pGame, pGame->game_name, pGame->host_name, pGame->map->file_path);
	
	// Initially game goes into a timeout state due to no players.
	pGame->TimeoutBegin();
	
	// Notify users.
	OnGameStateChange(pGame, NULL, WSP_ADD_GAME);
	FlushGameStateChanges(-1);
	
	return pGame;
	
FAIL:
	pGame->Destroy();
	return NULL;
}


/*
 * Game::Destroy
 * 
 */
void Game::Destroy()
{
	LOG("*** Destroy game; idx=%u", Games - this);
	
	
	if(state >= GAME_STATE_LOBBY)
	{
		// Notify users.
		OnGameStateChange(this, NULL, WSP_REM_GAME);
		FlushGameStateChanges(-1);
	
		// Destroy any connected clients.
		ITERATE_BITSET(pmask_clients)
		{
			players[i]->Destroy();
		}
	
		// Disarm timer.
		SetTimer(&tmr, 0, 0);
		
		// Remove from global game list & free.
		LIST_DEL(lstGames, this);
	}
	
	// Cleanup the rest.
	if (ins_buf)
		munmap(ins_buf, CFG_MAX_GAME_STREAM);
	
	if (tinf)
		munmap(tinf, CFG_MAX_TURNS * sizeof(turn_info));
	
	// Saftey for referencing free games.
	state = 0;
	
	// Free memory.
	Games.Free(this);
}


/*
 * Game::TimeoutBegin
 *
 */
void Game::TimeoutBegin()
{
	if(!idle_timeout)
	{
		// Reprogram the timer to fire upon expiration and signal the game should be destroyed.
		SetTimer(&tmr, CFG_IDLE_GAME_TIMEOUT * 1000, 0);
		idle_timeout = true;
		
		LOG("Idle timeout armed for game %u (%s)", Games-this, game_name);
	}
}

/*
 * Game::TimeoutCancel
 *
 */
void Game::TimeoutCancel()
{
	if(idle_timeout)
	{
		// Restore timer to regular interval and clear the timeout signal.
		SetTimer(&tmr, 0, turn_period);
		idle_timeout = false;
		
		LOG("Idle timeout cancelled for game %u (%s)", Games-this, game_name);
	}
}


/*
 * Game:OnTimerExpire
 *
 */
void Game::OnTimerExpire()
{
	if(idle_timeout)
	{
		LOG("Game %u (%s) has timed out due to idle.", Games-this, game_name);
		Destroy();
		return;
	}
	
	switch(state)
	{
		// Just flush any dirty state.
		case GAME_STATE_LOBBY:
		{
			if(dirty_lobby_state)
			{
				FlushLobbyState(pmask_players);
				dirty_lobby_state = false;
			}
		} break;
	
		// We're waiting for all players to load.
		case GAME_STATE_LOAD:
		{
			if((pmask_loaded & pmask_players) == pmask_players)
			{
				wcp_ready_ex* pMsg = (wcp_ready_ex*) Scratch;

				ITERATE_BITSET(pmask_players | pmask_dummy_players)
				{
					pMsg->magic = WCP_MAGIC;
					pMsg->mid = WCP_READY_EX;
					pMsg->len = sizeof(wcp_ready_ex);
					pMsg->pid = WCP_PID(i);
					pMsg++;
				}
				
				Send(pmask_players, Scratch, ((byte*) pMsg) - Scratch);
				
				state = GAME_STATE_RUN;
				t_last = GetTickNs();
				
				LOG("Game load complete. Game has begun.");
			}
		} break;
	
		// Finalize current turn.
		case GAME_STATE_RUN:
		{
			const u64 t = GetTickNs();
			const u64 dt = t - t_last;
			t_last = t;
			t_accum += dt;
			
			u64 period = (t_accum / 1000000);
			t_accum = t_accum % 1000000;
			
			if(period > CFG_TURN_CLAMP)
			{
				period = CFG_TURN_CLAMP;
				
				LWARN("Clamped turn.");
			}
			
			// Finalize current turn.
			ins_turn->magic = WCP_MAGIC;
			ins_turn->len = ins_turn->len + sizeof(wcp_turn);
			ins_turn->mid = WCP_TURN;
			ins_turn->period = (u16) period;
			ins_turn->crc = (u16) wcp_crc32(ins_turn->input, ins_turn->len - sizeof(wcp_turn));
			
			// Advance beyond this final turn message; we may append removal messages after.
			ins_turn_ptr += ins_turn->len;
			
			// Append player-remove for those pending removal.
			ITERATE_BITSET(pmask_remove)
			{
				ins_rm->magic = WCP_MAGIC;
				ins_rm->mid = WCP_REMOVE;
				ins_rm->len = sizeof(wcp_remove);
				ins_rm->pid = WCP_PID(i);
				ins_turn_ptr += ins_rm->len;
			}
			
			pmask_remove = 0;
			
			// Record turn information.
			tinf[turn].ins_off = (u32) (ins_head - ins_buf);
			tinf[turn].ins_len = (u32) (ins_turn_ptr - ins_head);
			tinf[turn].period = period;
			
			// ins_head and ins_turn now point to the start of turn data for the next turn.
			ins_head = ins_turn_ptr;
			
			// Advance turn.
			turn++;
			
			
			/*
			 * Check if any players (not observers) have begun stalling.
			 *
			 * A player will exit being marked as stalled only once it has reported (WCP_TURN_DONE) that it has
			 * reached the current turn - 1.
			 * 
			 */
			ITERATE_BITSET(pmask_players)
			{
				if(players[i]->HasStalled())
					pmask_stall |= PMASK(i);
			}
		}
	}
	
	// Pings are always sent irrespective of state; war3 uses this as a heartbeat, requiring
	// regular pings despite receiving other messages.
	if(GetTickCount() - last_ping > CFG_PING_INTERVAL)
	{
		wcp_ping ping;
		
		ping.magic = WCP_MAGIC;
		ping.mid = WCP_PING;
		ping.len = sizeof(wcp_ping);
		ping.tick = GetTickCount();
		
		Send(pmask_clients, &ping, sizeof(ping));
		
		last_ping = GetTickCount();
	}

	// Send queued data.
	u32 pmask_write_fail = 0; /* Players for whom writev() failed in the subsequent loop. */
	
	ITERATE_BITSET(pmask_clients | pmask_connected)
	{
		iovec iov[2];
		int iov_len = 0;
		ssize_t iov_data_total = 0;
		ssize_t result;
		Player* p = GetPlayer(i);
		
		// Unicast sends.
		if(p->psb_len)
		{
			iov[iov_len].iov_base = p->psb;
			iov[iov_len].iov_len = p->psb_len;
			iov_data_total += iov[iov_len].iov_len;
			iov_len++;
			
			p->psb_len = 0;
		}
		
		// Game stream.
		if(PMASK(i) & pmask_loaded)
		{
			if(p->ins_head_ptr < ins_head)
			{
				iov[iov_len].iov_base = p->ins_head_ptr;
				iov[iov_len].iov_len = ins_head - p->ins_head_ptr;
				iov_data_total += iov[iov_len].iov_len;
				iov_len++;
			
				p->ins_head_ptr = ins_head;
			}
		}
		
		// Send off unicast + stream.
		if((result = writev(p->s, iov, iov_len)) != iov_data_total)
		{
			pmask_write_fail |= PMASK(i);
			
			LERR("writev() for client %s (pid:%u): %d != %d", p->name, p->pid, result, iov_data_total);
		}
	}
	
	// Destroy any clients for which I/O failed.
	ITERATE_BITSET(pmask_write_fail)
	{
		players[i]->Destroy();
	}
}


/*
 * Game:AddPlayer
 * 
 */
bool Game::AddPlayer(Player* pPlayer)
{
	u8 pid;
	
	
	// Real players only allowed during lobby state.
	if(state != GAME_STATE_LOBBY)
	{
		LOG("Cannot join player%s; game is not in lobby state.", pPlayer->name);
		return false;
	}
	
	// Allocate PID.
	if(!(pid = ffsbit(~pmask_players & pmask_valid_players)))
	{
		LOG("Cannot join player %s; no PID available.", pPlayer->name);
		return false;
	}
	
	// ffsbit returns 1-based bit index.
	pid--;
	
	// Beyond this point the player is considerd a member of the game and must be removed.
	pPlayer->pid = pid; 
	players[pid] = pPlayer;
	pPlayer->g = this;
	pPlayer->ins_head_ptr = ins_buf;
	strcpy(pname[pid], pPlayer->name);
	
	pmask_players |= PMASK(pid);
	pmask_clients |= PMASK(pid);
	pmask_connected |= PMASK(pid);
	pmask_xferred &= ~PMASK(pid);
	pmask_loaded &= ~PMASK(pid);
	pmask_stall &= ~PMASK(pid);
	pmask_remove &= ~PMASK(pid);
	
	// Assign to a slot.
	if(!MovePlayer(pPlayer, SLOT_NULL, WCP_STATE_OPEN, WCP_CTRL_HUMAN, SLOT_NULL))
	{
		LOG("Cannot join player %s; no slot available.", pPlayer->name);
		return false;
	}

	// 
	byte* p = Scratch;
	byte* pb;
	
	// Send startup (which is lobby state and some extras, like PID assignment)
	WRITE_WCP_HDR(WCP_STARTUP);
	WRITE_WORD(map->slot_count * sizeof(wcp_slot) + 7);
	WRITE_BYTE(map->slot_count);
	WRITE_VOID(slots, map->slot_count * sizeof(wcp_slot));
	WRITE_DWORD(seed);
	WRITE_BYTE(3);
	WRITE_BYTE(map->max_players);
	WRITE_BYTE(WCP_PID(pPlayer->pid));
	WRITE_DWORD(0);
	WRITE_DWORD(0);
	WRITE_DWORD(0);
	WRITE_DWORD(0);
	WRITE_WCP_LEN();
	
	// Send player information about everyone else.
	ITERATE_BITSET(pmask_players & ~PMASK(pPlayer->pid))
	{
		WRITE_WCP_HDR(WCP_PLAYER);
		WRITE_DWORD(1);
		WRITE_BYTE(WCP_PID(i));
		WRITE_STRING(GetPlayer(i)->name);
		WRITE_WORD(1);
		WRITE_NULL(32);
		WRITE_WCP_LEN();
	}
	
	// Also player information about observers dummys.
	ITERATE_BITSET(pmask_dummy_players)
	{
		WRITE_WCP_HDR(WCP_PLAYER);
		WRITE_DWORD(1);
		WRITE_BYTE(WCP_PID(i));
		WRITE_STRING_CONST("System#%u", i);
		WRITE_WORD(1);
		WRITE_NULL(32);
		WRITE_WCP_LEN();
	}
	
	// Map verification/check.
	WRITE_WCP_HDR(WCP_MAP_QUERY);
	WRITE_DWORD(1);
	WRITE_STRING(map->file_path);
	WRITE_DWORD(map->map_file_sz);
	WRITE_DWORD(map->map_crc);
	WRITE_DWORD(map->map_xor);
	WRITE_VOID(map->map_sha, sizeof(map->map_sha));
	WRITE_WCP_LEN();
	
	// Send it all off the new player.
	Send(PMASK(pPlayer->pid), Scratch, p-Scratch);
	
	// Now inform everyone else about this new player.
	WRITE_WCP_HDR(WCP_PLAYER);
	WRITE_DWORD(1);
	WRITE_BYTE(WCP_PID(pPlayer->pid));
	WRITE_STRING(pPlayer->name);
	WRITE_WORD(1);
	WRITE_NULL(32);
	WRITE_WCP_LEN();
	
	// Send to everyone except this new player.
	Send(pmask_players & ~PMASK(pPlayer->pid), pb, WCP_HDR(pb)->len);
	
	LOG("Entered player %s as player (pid:%u)", pPlayer->name, pPlayer->pid);
	
	// Cancel any pending timeout now there's atleast one player.
	TimeoutCancel();
	
	// Successfully added to game.
	return true;
}


/*
 * Game:AddObserver
 * 
 */
bool Game::AddObserver(Player* pPlayer)
{
	u8 pid;
	
	// Game must be running.
	if(state != GAME_STATE_RUN)
	{
		LOG("Cannot join observer %s; game is not in run state.", pPlayer->name);
		return false;
	}
	
	// Game settings must support observers, as indicated by the presence of dummys.
	if(!pmask_dummy_players)
	{
		LOG("Cannot join observer %s; game does not support observers.", pPlayer->name);
		return false;
	}
	
	// Allocate PID from the valid observer PID pool.
	if(!(pid = ffsbit(~(pmask_valid_players | pmask_dummy_players))))
	{
		LOG("Cannot join observer %s; no PID available.", pPlayer->name);
		return false;
	}
	
	// ffsbit returns 1-based bit index.
	pid--;
	
	// Beyond this point the player is considerd a member of the game and must be removed.
	pPlayer->pid = pid; 
	players[pid] = pPlayer;
	pPlayer->g = this;
	pPlayer->ins_head_ptr = ins_buf;
	
	pmask_clients |= PMASK(pid);
	pmask_connected |= PMASK(pid);
	pmask_xferred &= ~PMASK(pid);
	pmask_loaded &= ~PMASK(pid);
	pmask_stall &= ~PMASK(pid);
	pmask_remove &= ~PMASK(pid);
	
	// 
	byte* p = Scratch;
	byte* pb;
	
	// Send startup (which is lobby state and some extras, like PID assignment)
	WRITE_WCP_HDR(WCP_STARTUP);
	WRITE_WORD(map->slot_count * sizeof(wcp_slot) + 7);
	WRITE_BYTE(map->slot_count);
	WRITE_VOID(slots, map->slot_count * sizeof(wcp_slot));
	WRITE_DWORD(seed);
	WRITE_BYTE(3);
	WRITE_BYTE(map->max_players);
	WRITE_BYTE(virtual_obs_pid);
	WRITE_DWORD(0);
	WRITE_DWORD(0);
	WRITE_DWORD(0);
	WRITE_DWORD(0);
	WRITE_WCP_LEN();
	
	// Send player information about everyone else.
	// This comes from the slots as the Player objects themselves may no longer exist.
	for(u8 i = 0; i < map->max_players; i++)
	{
		if(slots[i].pid)
		{
			WRITE_WCP_HDR(WCP_PLAYER);
			WRITE_DWORD(1);
			WRITE_BYTE(slots[i].pid);
			WRITE_STRING(pname[slots[i].pid-1]);
			WRITE_WORD(1);
			WRITE_NULL(32);
			WRITE_WCP_LEN();
		}
	}
	
	// Also player information about additional observers dummys.
	ITERATE_BITSET(pmask_dummy_players)
	{
		if(WCP_PID(i) != virtual_obs_pid)
		{
			WRITE_WCP_HDR(WCP_PLAYER);
			WRITE_DWORD(1);
			WRITE_BYTE(WCP_PID(i));
			WRITE_STRING_CONST("System#%u", i);
			WRITE_WORD(1);
			WRITE_NULL(32);
			WRITE_WCP_LEN();
		}
	}
	
	// Map verification/check.
	WRITE_WCP_HDR(WCP_MAP_QUERY);
	WRITE_DWORD(1);
	WRITE_STRING(map->file_path);
	WRITE_DWORD(map->map_file_sz);
	WRITE_DWORD(map->map_crc);
	WRITE_DWORD(map->map_xor);
	WRITE_VOID(map->map_sha, sizeof(map->map_sha));
	WRITE_WCP_LEN();
	
	// Send it all off the new player.
	Send(PMASK(pPlayer->pid), Scratch, p-Scratch);
	
	// Send lobby state.
	FlushLobbyState(PMASK(pPlayer->pid));
	
	LOG("Entered player %s as observer (pid:%u)", pPlayer->name, pPlayer->pid);
	
	// Cancel any pending timeout now there's atleast one player.
	TimeoutCancel();
	
	return true;
}


/*
 * Game:RemovePlayer
 * 
 */
void Game::RemovePlayer(Player* pPlayer)
{
	const u8 pid = pPlayer->pid;
	const u8 sid = pPlayer->sid;
	const u32 pmask = PMASK(pid);
	
	// Some invariant checks.
	ASSERT(pPlayer->g == this);
	ASSERT(pid != PID_NULL);
	ASSERT(pmask_clients & pmask);
	
	// Release PID.
	players[pPlayer->pid] = NULL;
	pmask_players &= ~pmask;
	pmask_clients &= ~pmask;
	pmask_connected &= ~pmask;
	pmask_xferred &= ~pmask;
	pmask_loaded &= ~pmask;
	pmask_stall &= ~pmask;
	
	if(pPlayer->sid != SLOT_NULL)
	{
		// We must preserve the lobby state once the simulation has begun for it's
		// required for observers for elsewise it may lead to desynchronization.
		if(state <= GAME_STATE_LOAD)
		{
			ASSERT(slots[sid].pid == WCP_PID(pid));
		
			slots[sid].pid = 0;
			slots[sid].state = WCP_STATE_OPEN;
			dirty_lobby_state = true;
		
			// Normal remove player.
			wcp_remove rm;
			rm.magic = WCP_MAGIC;
			rm.mid = WCP_REMOVE;
			rm.len = sizeof(wcp_remove);
			rm.pid = WCP_PID(pPlayer->pid);
		
			Send(pmask_players, &rm, rm.len);
		}
	
		// Elsewise if the game simulation is running, removal must be part of the
		// game stream as to avoid desynchronization (and so observers know)
		else
		{
			pmask_remove |= pmask;
		}
	}
	
	// Game now empty of all players (and observers)? Begin the timeout.
	if(!pmask_clients)
		TimeoutBegin();
	
	// Debugging
	pPlayer->g = NULL;
	pPlayer->sid = SLOT_NULL;
	pPlayer->pid = PID_NULL;
}


/*
 * Game:Send
 * 
 */
void Game::Send(u32 pmask, void* pData, u32 Len)
{
	ITERATE_BITSET(pmask & pmask_connected)
	{
		GetPlayer(i)->Send(pData, Len);
	}
}


/*
 * Game:MovePlayer
 * 
 */
bool Game::MovePlayer(Player* pPlayer, u8 dst_sid, u8 match_state, u8 match_ctrl, u8 match_team)
{
	if(dst_sid == SLOT_NULL)
	{
		// Start searching at the next slot from the player if they are already assigned.
		dst_sid = pPlayer->sid != SLOT_NULL ? pPlayer->sid+1 : 0;
		
		for(u8 i = 0; i < map->slot_count-1; i++, dst_sid++)
		{
			dst_sid %= map->slot_count;
			
			if((match_state == SLOT_NULL || match_state == slots[dst_sid].state) &&
			   (match_ctrl == SLOT_NULL || match_ctrl == slots[dst_sid].ctrl) &&
			   (match_team == SLOT_NULL || match_team == slots[dst_sid].team))
			{
				goto FOUND_MATCH;
			}
		}
		
		// No match.
		return false;
	}
	
FOUND_MATCH:
	if(dst_sid == pPlayer->sid)
		return true; 
	
	// If no current slot, then just assign.
	if(pPlayer->sid == SLOT_NULL)
	{
		wcp_slot& dst = slots[dst_sid];
		
		dst.state = WCP_STATE_OCCUPIED;
		dst.ctrl = WCP_CTRL_HUMAN;
		dst.pid = pPlayer->pid+1;
	}
	
	// Elsewise exchange.
	else
	{
		wcp_slot& dst = slots[dst_sid];
		wcp_slot& src = slots[pPlayer->sid];
		
		SWAP(dst.state, src.state);
		SWAP(dst.pid, src.pid);
		SWAP(dst.ai, src.ai);
		
		if(src.pid)
			players[src.pid-1]->sid = pPlayer->sid;
	}
	
	pPlayer->sid = dst_sid;
	dirty_lobby_state = true;
	
	return true;
}


/*
 * Game::FlushLobbyState
 * 
 */
void Game::FlushLobbyState(u32 pmask)
{
	byte* p = Scratch;
	byte* pb;

	WRITE_WCP_HDR(WCP_LOBBY);
	WRITE_WORD(map->slot_count * sizeof(wcp_slot) + 7);
	WRITE_BYTE(map->slot_count);
	WRITE_VOID(slots, map->slot_count * sizeof(wcp_slot));
	WRITE_DWORD(seed);
	WRITE_BYTE(3);
	WRITE_BYTE(map->max_players);
	WRITE_WCP_LEN();
	
	Send(pmask, WCP_HDR(Scratch), WCP_HDR(Scratch)->len);
}


/*
 * Game::TurnAppend
 * 
 */
void Game::TurnAppend(u8 src_pid, void* pData, u16 Len)
{
	// War3 has a fixed limit of 1460 bytes per turn protocol layer message, exceeding
	// this requires input to be spilled over one or more WCP_TURN2 messages, the end of
	// signified with a final WCP_TURN.
	if(ins_turn->len + sizeof(wcp_cmd) + Len >= 1460)
	{
		// Finalize the current turn message.
		ins_turn->magic = WCP_MAGIC;
		ins_turn->mid = WCP_TURN2;
		ins_turn->len = ins_turn->len + sizeof(wcp_turn);
		ins_turn->period = 0; // Only the final WCP_TURN specifies period.
		ins_turn->crc = (u16) wcp_crc32(ins_turn->input, ins_turn->len - sizeof(wcp_turn));
		
		// Begin anew.
		ins_turn_ptr += ins_turn->len;
	}
	
	// Append to current turn payload.
	wcp_cmd* cmd = (wcp_cmd*) (ins_turn->input + ins_turn->len);
	
	cmd->pid = WCP_PID(src_pid);
	cmd->len = Len;
	memcpy(cmd->data, pData, Len);
	ins_turn->len += sizeof(wcp_cmd) + Len;
}


/*
 * Game::Start
 * 
 */
bool Game::Start()
{
	if(state != GAME_STATE_LOBBY)
	{
		LWARN("Unable to start game; not in lobby state.");
		return false;
	}
	
	// Verify that all players have the map.
	if(pmask_xferred != pmask_players)
	{
		LWARN("Unable to start game; pending map transfer.");
		return false;
	}
	
	// Flush any dirty lobby state.
	FlushLobbyState(pmask_players);
	
	// Actually start the game.
	wcp_hdr startmsg[2] = 
	{ 
		{ WCP_MAGIC, WCP_COUNT_BEGIN, sizeof(wcp_hdr) }, 
		{ WCP_MAGIC, WCP_COUNT_END, sizeof(wcp_hdr) } 
	};
	
	Send(pmask_players, &startmsg, sizeof(startmsg));
	
	state = GAME_STATE_LOAD;
	
	LOG("Game has started; entered load state.");
	
	return true;
}


/*
 * Game::Chat
 * 
 */
void Game::Chat(u32 pmask, Player* src, u32 flags, const char* pFormat, ...)
{
	wcp_chat_ex* pMsg = (wcp_chat_ex*) Scratch;
	char* pDstText;
	
	va_list va;
	va_start(va, pFormat);
	
	pMsg->magic = WCP_MAGIC;
	pMsg->mid = WCP_CHAT_EX;
	pMsg->count = 0;
	pMsg->pid = src ? WCP_PID(src->pid) : 0; /* Zero source PID signifies system messages. */
	
	switch(state)
	{
		case GAME_STATE_LOBBY:
		{
			pMsg->len = sizeof(wcp_chat_ex) - sizeof(u32);
			pMsg->ctrl = WCP_CHAT_CTRL_MSG_LOBBY;
			pDstText = pMsg->lobby.text;
		} break;
		
		case GAME_STATE_RUN:
		{
			pMsg->len = sizeof(wcp_chat_ex);
			pMsg->ctrl = WCP_CHAT_CTRL_MSG_GAME;
			pMsg->game.flags = flags;
			pDstText = pMsg->game.text;
		} break;
		
		default:
		{
			LWARN("Invalid state for client to be receiving chat '%s'", pFormat);
			return;
		}
	}
	
	// Observer chat needs to specially generated.
	if(src && !(pmask_players & PMASK(src->pid)))
	{
		int prefix_len = sprintf(pDstText, "[Observer] |cff81BAFF%s:|r ", src->name);
		
		// Note the lack of null.
		pDstText += prefix_len;
		pMsg->len += prefix_len;
		
		// Mark as a system message (handled by warex)
		pMsg->pid = 0;
	}
		
	pMsg->len += vsprintf(pDstText, pFormat, va) + 1;
	
	Send(pmask, pMsg, pMsg->len);
}


// Fluff
void OnPlayerEvt(void* p, u32 events)
{
	((Player*) p)->OnSocketEvent(events);
}


/*
 * CreatePlayer
 *
 */
Player* CreatePlayer(int s, const char* pName, u32 Addr)
{
	Player* pPlayer;
	
	if(!(pPlayer = Players.Allocate()))
	{
		LERR("Failed to allocate new player object");
		return NULL;
	}
	
	memzero(pPlayer, sizeof(*pPlayer));
	
	pPlayer->s = s;
	pPlayer->pfsockevt = OnPlayerEvt;
	pPlayer->addr = Addr;
	pPlayer->sid = SLOT_NULL;
	pPlayer->pid = PID_NULL;
	strncpy(pPlayer->name, pName, sizeof(pPlayer->name));
	
	if(!(pPlayer->psb = (byte*) malloc(CFG_PLAYER_SNDBUF_SZ)))
	{
		LERR("Failed to allocate player sendbuf");
		return NULL;
	}
	
	if(!(pPlayer->rxm = (byte*) malloc(CFG_PLAYER_RXMB_SZ)))
	{
		LERR("Failed to allocate player rxmb");
		return NULL;
	}
	
	// Register for events with epoll.
	epoll_event ev;
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.ptr = pPlayer;
	
	if(epoll_ctl(efd, EPOLL_CTL_ADD, pPlayer->s, &ev) < 0)
	{
		LERR("Failed to add player socket to epoll");
		return NULL;
	}
	
	return pPlayer;
}


/*
 * Player::OnSocketEvent
 * 
 */
void Player::OnSocketEvent(u32 events)
{
	if(events & EPOLLIN)
	{
		ssize_t r;
		
		if((r = recv(s, rxm+rxm_len, CFG_PLAYER_RXMB_SZ - rxm_len, 0)) < 0)
		{
			LERR("Failure during recv()");
			goto FAIL;
		}
		
		if(!r)
		{
			LOG("Connection closed remotely gracefully.");
			goto FAIL;
		}
		
		rxm_len += r;
		
		union
		{
			byte* p;
			wcp_hdr* hdr;
		}; p = rxm;
		
		while(rxm_len)
		{
			bool result;
			
			if(rxm_len < sizeof(wcp_hdr))
			{
				LWARN("Insufficient data for message header.");
				break;
			}
			
			if(hdr->magic != WCP_MAGIC)
			{
				LERR("Corrupt message received.");
				goto FAIL;
			}
			
			if(rxm_len < hdr->len)
			{
				LWARN("Insufficient data for message.");
				break;
			}
			
			switch(hdr->mid)
			{
				case WCP_SUBMIT: result = OnSubmit((wcp_submit*) hdr); break;
				case WCP_TURN_DONE: result = OnTurnDone((wcp_turn_done*) hdr); break;
				case WCP_PONG: result = OnPong((wcp_ping*) hdr); break;
				case WCP_LEAVE: result = OnLeave((wcp_leave*) hdr); break;
				case WCP_CHAT: result = OnChat((wcp_chat*) hdr); break;
				case WCP_MAP_RESULT: result = OnMapResult((wcp_map_result*) hdr); break;
				case WCP_READY: result = OnReady((wcp_ready*) hdr); break;
			
				default:
					LERR("Received unknown message: 0x%X", hdr->mid);
					result = false;
			}
			
			if(!result)
				goto FAIL;
			
			rxm_len -= hdr->len;
			p += hdr->len;
		}
		
		if(rxm_len)
		{
			memmove(rxm, p, rxm_len);
			
			LWARN("Partial message");
		}
	}
	
	if(events & (EPOLLERR | EPOLLHUP))
	{
		int err = 0;
		socklen_t errlen = sizeof(err);
		getsockopt(s, SOL_SOCKET, SO_ERROR, (void*) &err, &errlen);
		errno = err;
			
		LERR("Socket error");
		goto FAIL;
	}
	
	// Success
	return;
	
FAIL:
	Destroy();
}


/*
 * Player::Destroy
 * 
 */
void Player::Destroy()
{
	LOG("Destroy player %s", name);
	
	if(g)
		g->RemovePlayer(this);
	
	free(rxm);
	free(psb);
	close(s);
	
	Players.Free(this);
}


/*
 * Player::Send
 *
 */
void Player::Send(void* pData, u32 Len)
{
	if(psb_len + Len >= CFG_PLAYER_SNDBUF_SZ)
	{
		LERR("Exceeded player send buffer.");
		return;
	}
	
	memcpy(psb+psb_len, pData, Len);
	psb_len += Len;
}


/*
 * Player::StartGame
 * 
 */
void Player::StartGame()
{
	// Actually start the game.
	wcp_hdr startmsg[2] = 
	{ 
		{ WCP_MAGIC, WCP_COUNT_BEGIN, sizeof(wcp_hdr) }, 
		{ WCP_MAGIC, WCP_COUNT_END, sizeof(wcp_hdr) } 
	};
	
	Send(&startmsg, sizeof(startmsg));
}


/*
 * Player::IsObserver
 * 
 */
bool Player::IsObserver()
{
	ASSERT(pid != PID_NULL);
	ASSERT(g != NULL);
	
	if(~g->pmask_players & PMASK(pid))
		return true;
	
	else
		return false;
}


/*
 * Player::HasStalled
 * 
 */
bool Player::HasStalled()
{
	return ((g->turn - cur_turn) * (CFG_STALL_THRESHOLD / g->turn_period) >= CFG_STALL_THRESHOLD);
}


/*
 * Player::OnSubmit
 * 
 */
bool Player::OnSubmit(wcp_submit* pMsg)
{
	/*
	 * As of 1.29, observers errorneously submit input for some bizarre reason. Testing
	 * suggests ignoring it renders no undesirable side-effects (such as desynchronization)
	 * 
	 */
	if(!IsObserver())
		g->TurnAppend(this->pid, pMsg->data, pMsg->len - sizeof(wcp_submit));

	return true;
}


/*
 * Player::ComputeStreamConsume
 * 
 */
uint Player::ComputeStreamConsume()
{
	return 0;
	
}

/*
 * Player::OnTurnDone
 *
 */
bool Player::OnTurnDone(wcp_turn_done* pMsg)
{
	if(turn_ack >= g->turn)
	{
		LERR("Unexpected acknowledgement for future turn.");
		return false;
	}
	
	// This is the turn that was *completed*
	turn_info& ti = g->tinf[turn_ack];
	
	/*
	 * If we already have a state checksum result then compare ours with it, 
	 * if not then we're the first to complete this turn and we become the
	 * reference "correct" game-state for all other players for this turn.
	 * 
	 * In other words: whichever player (not observer) completes the turn
	 * first has their game-state used as the authoritive reference. We
	 * obviously need to improve upon this at some point.
	 * 
	 */
	if(!ti.pmask_done && !IsObserver())
		ti.state_csum = pMsg->state_crc;
	
	ti.pmask_done |= PMASK(pid) & g->pmask_players;
	
	if(ti.pmask_done && pMsg->state_crc != ti.state_csum)
	{
		// TODO: Desynchronization detected.
	}
	
	// Adjust simulation time consumed
	sim_time += ti.period;
	
	// Next turn.
	turn_ack++;
	
	return true;
}

/*
 * Player::OnLeave
 * 
 */
bool Player::OnLeave(wcp_leave* pMsg)
{
	return false;
}


/*
 * Player::OnPong
 * 
 */
bool Player::OnPong(wcp_ping* pMsg)
{
	return true;
}


/*
 * Player::OnChat
 * 
 */
bool Player::OnChat(wcp_chat* pMsg)
{
	const u8 recipient_count = pMsg->recipient_count;
	const u8 src_pid = pMsg->data[recipient_count+0];
	const u8 ctrl = pMsg->data[recipient_count+1];
	const u32 param = *(u32*) &pMsg->data[recipient_count+2];
	const char* text = (char*) &pMsg->data[recipient_count + (ctrl == WCP_CHAT_CTRL_MSG_GAME ? 6 : 2)];
		
	
	// If not currently in lobby state, and this message operates on the lobby then ignore.
	if(ctrl < WCP_CHAT_CTRL_MSG_GAME && (g->state != GAME_STATE_LOBBY || IsObserver()))
		PLOG("Ignored chat lobby control message; game not in lobby-state or is observer.");
	
	// Elsewise if game chat and the game is not running, then ignore.
	else if(ctrl == WCP_CHAT_CTRL_MSG_GAME && g->state < GAME_STATE_RUN)
		PLOG("Ignored game chat; game has not started.");
	
	// Valid context.
	else
	{
		switch(ctrl)
		{
			case WCP_CHAT_CTRL_SET_COLOR:
			case WCP_CHAT_CTRL_SET_RACE:
			case WCP_CHAT_CTRL_SET_HCAP:
			{
				PLOG("Ignoring unimplemented chat-ctrl message %u", ctrl);
			} break;
			
			case WCP_CHAT_CTRL_SET_TEAM:
			{
				g->MovePlayer(this, PID_NULL, WCP_STATE_OPEN, WCP_CTRL_HUMAN, param);
			} break;
			
			case WCP_CHAT_CTRL_MSG_LOBBY:
			case WCP_CHAT_CTRL_MSG_GAME:
			{
				PLOG("CHAT(src:%u flags:0x%X) %s", src_pid, param, text);
				
				if(text[0] == '!')
					ProcessChatCommand(text+1);
				
				g->Chat(g->pmask_clients & ~PMASK(pid), this, param, "%s", text);
				
			} break;
			
			default:
			{
				PLOG("Ignoring invalid chat-ctrl %u", ctrl);
			}
		}
	}
	
	return true;
}


/*
 * Player::OnMapResult
 * 
 */
bool Player::OnMapResult(wcp_map_result* pMsg)
{
	PLOG("Map check result: %u", pMsg->result);
	
	if(pMsg->result)
	{
		g->pmask_xferred |= PMASK(pid);
		
		// For observers this triggers the game start.
		if(IsObserver())
			StartGame();
	}
	
	return true;
}


/*
 * Player::OnReady
 * 
 */
bool Player::OnReady(wcp_ready* pMsg)
{
	PLOG("Load complete.");

	g->pmask_loaded |= PMASK(pid);
	
	// For observers this completes the load immediately.
	// As usual with observers we rely on the lobby-state.
	if(IsObserver())
	{
		wcp_ready_ex* pMsg = (wcp_ready_ex*) Scratch;

		for(u8 i = 0; i < g->map->slot_count; i++)
		{
			if(g->slots[i].pid)
			{
				pMsg->magic = WCP_MAGIC;
				pMsg->mid = WCP_READY_EX;
				pMsg->len = sizeof(wcp_ready_ex);
				pMsg->pid = g->slots[i].pid;
				pMsg++;
			}
		}
				
		Send(Scratch, ((byte*) pMsg) - Scratch);
	}
	
	return true;
}


/*
 * Player::ProcessChatCommand
 * 
 */
void Player::ProcessChatCommand(const char* pText)
{
	switch(*pText)
	{
		case 'c':
		{
			for(u8 i = 0; i < g->map->max_players; i++)
			{
				if(g->slots[i].state == WCP_STATE_OPEN)
				{
					g->slots[i].state = WCP_STATE_OCCUPIED;
					g->slots[i].ctrl = WCP_CTRL_AI;
					g->slots[i].ai = i < 5 ? WCP_AI_EASY : WCP_AI_HARD;
					
					g->dirty_lobby_state = true;
				}
			}
		} break;
		
		case 's':
		{
			g->Start();
		} break;
	}
}



/*
 * OnGameStateChange
 * 
 */
void OnGameStateChange(Game* pGame, war3_map* pMap, u8 Operation)
{
	union
	{
		wsp_add_game* pMsgAdd;
		wsp_rem_game* pMsgRem;
		byte* pMsg;
		char* ps;
	};
	
	pMsg = UserBuffer + UserBufferLen;
	wsp_hdr* pHdr = (wsp_hdr*) pMsg;
	pMap = pGame ? pGame->map : pMap;
	
	switch(Operation)
	{
		case WSP_ADD_GAME:
		{
			pMsgAdd->game_id = 1 + (pGame ? ARRAYSIZE(Maps) + (Games - pGame) : (pMap - Maps));
			pMsgAdd->game_key = 0;
			pMsgAdd->slots_total = pMap->slot_count;
			pMsgAdd->slots_players = pMap->max_players;
			pMsgAdd->slots_used = pGame ? popcnt(pGame->pmask_players) : 0;
			pMsgAdd->map_flags = pMap->map_flags;
			pMsgAdd->map_xor = pMap->map_xor;
			pMsgAdd->host_port = CFG_GAME_PORT;
			pMsgAdd->host_addr = env.local_ipv4;
			
			ps = pMsgAdd->ect;
			
			strcpy(ps, pGame ? pGame->game_name : pMap->game_name); ps += strlen(ps) + 1;
			strcpy(ps, pGame ? pGame->host_name : "System"); ps += strlen(ps) + 1;
			strcpy(ps, pMap->file_path); ps += strlen(ps) + 1;
		} break;
		
		case WSP_REM_GAME:
		{
			pMsgRem->game_id = 1 + ARRAYSIZE(Maps) + (Games - pGame);
			ps += sizeof(wsp_rem_game);
		} break;
	}
	
	pHdr->magic = WSP_MAGIC;
	pHdr->mid = Operation;
	pHdr->len = (pMsg - ((byte*) pHdr));
	
	UserBufferLen += pHdr->len;
}


/*
 * FlushGameStateChanges
 * 
 */
bool FlushGameStateChanges(int s)
{
	if(s != -1)
	{
		if(send(s, UserBuffer, UserBufferLen, 0) != UserBufferLen)
		{
			LERR("Failed to send game-state-buffer (unicast)");
			return false;
		}
	}
	
	else
	{
		for(uint i = 0; i < UsersLen; i++)
		{
			if(send(hUsers[i], UserBuffer, UserBufferLen, 0) != UserBufferLen)
			{
				LERR("Failed to send game-state-buffer to s%u", hUsers[i]);
			
				// Disconnect
				close(hUsers[i]);
			
				// Remove from list.
				memmove(&hUsers[i], &hUsers[i + 1], (--UsersLen - i) * sizeof(int));
				i--;
			}
		}
	}
	
	UserBufferLen = 0;
	
	return true; // Not meaningful.
}


/*
 * ServerStartup
 * 
 */
bool ServerStartup()
{
	sockaddr_in sa;
	socklen_t sa_len;
	int opt;
	
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = env.local_ipv4;
	sa.sin_port = htons(CFG_GAME_PORT);
	
	if((hListen = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
	{
		LERR("Failed to create game server socket.");
		return false;
	}
	
	if(setsockopt(hListen, IPPROTO_TCP, TCP_DEFER_ACCEPT, &(opt=CFG_DEFER_ACPT_TIME), sizeof(opt)) < 0 ||
	   setsockopt(hListen, IPPROTO_TCP, TCP_NODELAY,      &(opt=1), sizeof(opt)) < 0 ||
	   setsockopt(hListen, IPPROTO_TCP, TCP_KEEPIDLE,     &(opt=CFG_KEEPALIVE_IDLE), sizeof(opt)) < 0 ||
	   setsockopt(hListen, IPPROTO_TCP, TCP_KEEPCNT,      &(opt=CFG_KEEPALIVE_COUNT), sizeof(opt)) < 0 ||
	   setsockopt(hListen, IPPROTO_TCP, TCP_KEEPINTVL,    &(opt=CFG_KEEPALIVE_INTERVAL), sizeof(opt)) < 0 ||
	   setsockopt(hListen, IPPROTO_TCP, TCP_USER_TIMEOUT, &(opt=CFG_XMIT_TIMEOUT), sizeof(opt)) < 0 ||
	   setsockopt(hListen, SOL_SOCKET, SO_KEEPALIVE,      &(opt=1), sizeof(opt)) < 0 ||
	   setsockopt(hListen, SOL_SOCKET, SO_REUSEADDR,      &(opt=1), sizeof(opt)) < 0)
	{
		LERR("Failed to configure game server socket options.");
		return false;
	}
	
	if(bind(hListen, (sockaddr*) &sa, sizeof(sa)) < 0 || listen(hListen, CFG_TCP_QUEUE_DEPTH) < 0)
	{
		LERR("Failed to bind/listen game socket.");
		return false;
	}
	
	getsockname(hListen, (sockaddr*) &sa, &(sa_len = sizeof(sa)));
	
	LOG("Local server socket name: %s, %u", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
	
	// Register with epoll
	static FDEVTCB pfOnListen = OnGameListenEvt;
	
	epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.ptr = &pfOnListen;
	
	if(epoll_ctl(efd, EPOLL_CTL_ADD, hListen, &ev) < 0)
	{
		LERR("Failed to register game server socket with epoll.");
		return false;
	}
	
	// Pools
	Games.Initialize();
	Players.Initialize();
	
	return true;
}