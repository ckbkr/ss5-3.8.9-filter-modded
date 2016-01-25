#include"SS5Main.h"
#include"SS5Mod_socks5_redirect.h"

sqlite3 * db = NULL;
sqlite3_stmt * stmt = NULL;

UINT setInterface(struct _SS5ClientInfo *ci){
	char interface[64] = { 0 };
	char logString[128] = { 0 };
	
	pid_t pid;
	if( NOTTHREADED() )
		pid = getpid();
	else
		pid = (UINT)pthread_self();
	
	if( GetInterface(ci, interface) == OK ){
		struct ifreq it;
			
		memset((void*)&it,0,sizeof(struct ifreq));
		strncpy(it.ifr_name, interface, 10 );
		if( setsockopt(ci->appSocket, SOL_SOCKET, SO_BINDTODEVICE, (char *)&it, sizeof(struct ifreq)) < 0 ){
			// make this more serious so no connection can go through an unsecure network
			snprintf(logString,128,"[%u] setsockopt returning ERR",pid);
			SS5Modules.mod_logging.Logging(logString);
			return ERR;
		}
	}else{
		snprintf(logString,128,"[%u] getInterface returning ERR",pid);
		SS5Modules.mod_logging.Logging(logString);
		return ERR;
	}
	return OK;
}


UINT GetInterface( struct _SS5ClientInfo *ci, char * interface ){
  int rc;
  if( db == NULL ){
	  // Database not initialized yet
	
    char * sErrMsg = 0;
	rc = sqlite3_open(":memory:", &db);
	//sqlite3_open_v2(DATABASE, &db);
	sqlite3_exec(db, TABLE, NULL, NULL, &sErrMsg);
	


  }
  
  
	//rc = sqlite3_prepare_v2(db, "SELECT TUNNELID FROM MAPPINGS WHERE IP = ?", -1, &res, 0);    
    
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Failed to fetch data: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }    
    
    //rc = sqlite3_step(res);
    
    if (rc == SQLITE_ROW) {
        //printf("%s\n", sqlite3_column_text(res, 0));
    }
  
  
  FILE *pf;

  char logString[128];
	
  char IPFile[128] = IPFILE;

  char login[64] = { 0 };
  char inter[64] = { 0 };

	
  pid_t pid;
  if( NOTTHREADED() )
    pid = getpid();
  else
    pid = (UINT)pthread_self();
	
  if( (pf = fopen(IPFile,"r")) == NULL ) {
    ERRNO(0)
    return ERR;
  }
	
  //snprintf(logString,128,"[%u] have interface file",pid);
  //SS5Modules.mod_logging.Logging(logString);

  /* 
   *    Look for username 
   */
  while( fscanf(pf,"%s %s",login,inter) != EOF ) {
		if( STRCASEEQ(ci->Username,login,strlen(login)-1) ){
			// Authorized Addr found
			strcpy(interface,inter);
			//snprintf(logString,128,"[%u] assigned %s to user %s",pid,inter,ci->Username);
			//SS5Modules.mod_logging.Logging(logString);
			return OK;
		}		
  }

  if( fclose(pf) ) {
    ERRNO(0)
    return ERR;
  }

  return ERR;
	
}