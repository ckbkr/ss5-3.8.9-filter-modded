#ifndef SS5MOD_SOCKS5_REDIRECT_H
#define SS5MOD_SOCKS5_REDIRECT_H 1


//#define SS5_USE_REDIRECT 1
#define DATABASE "./mappings.sqlite"
#define IPFILE "/home/root/InterfacePairing.list"
#define TABLE "CREATE TABLE IF NOT EXISTS TTC (id INTEGER PRIMARY KEY, Route_ID TEXT, Branch_Code TEXT, Version INTEGER, Stop INTEGER, Vehicle_Index INTEGER, Day Integer, Time TEXT)"


#include <sqlite3.h>

UINT GetInterface( struct _SS5ClientInfo *ci, char * interface );

UINT setInterface(struct _SS5ClientInfo *ci);

#endif