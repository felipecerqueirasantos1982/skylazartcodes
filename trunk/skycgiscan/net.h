/* 
   Private CGI Scan, Do Not Distribute!

   skycgiscan 0.1 beta
   by skylazart - Jun/2005
*/

#ifndef __MYNET_H
#define __MYNET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

long net_resolve (char *dn);
int net_connect (char * dn, int p, int ttl);
int net_has_data (int fd, long ttl);

typedef struct sockaddr_in SA;

#endif
