#include"SS5Main.h"
#include"SS5Mod_authorization_redirect.h"
#include"SS5Mod_socks5_redirect.h"

UINT IPFilter( struct _SS5ClientInfo *ci ){
  FILE *pf;

  char logString[128];
	
	char IPFile[128] = IPFILE;

  char addr[64];
  char login[64];
	
	pid_t pid;
  if( NOTTHREADED() )
    pid = getpid();
  else
    pid = (UINT)pthread_self();
	
	
	snprintf(logString,128,"[%u] ip filter auth, source: %s", pid, ci->SrcAddr);
  SS5Modules.mod_logging.Logging(logString);
	
  if( (pf = fopen(IPFile,"r")) == NULL ) {
    ERRNO(0)
    return ERR;
  }
	
	snprintf(logString,128,"[%u] have file",pid);
  SS5Modules.mod_logging.Logging(logString);

  /* 
   *    Look for username and password into password file 
   */
  while( fscanf(pf,"%s %s",addr,login) != EOF ) {
		if( STRCASEEQ(ci->SrcAddr,addr,15) ){
			// Authorized Addr found
			strcpy(ci->Username,login);
			snprintf(logString,128,"[%u] authorized %s",pid,ci->Username);
      SS5Modules.mod_logging.Logging(logString);
			return OK;
		}		
  }

  if( fclose(pf) ) {
    ERRNO(0)
    return ERR;
  }

  return ERR;

}
