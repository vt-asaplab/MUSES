#ifndef __CMPC_CONFIG
#define __CMPC_CONFIG
const static int abit_block_size = 1024;
const static int fpre_threads = 1;
#define LOCALHOST

#ifdef __clang__
	#define __MORE_FLUSH
#endif

//#define __debug
const static char *IP[] = {""
,	"127.0.0.1"    // Server 1
,	"127.0.0.1"    // Server 2
,	"127.0.0.1"    // Server 3
, 	"127.0.0.1"    // Server 4
, 	"127.0.0.1"    // Server 5
,	"127.0.0.1"};  // Server 6

const static bool lan_network = false;
#endif// __C2PC_CONFIG
