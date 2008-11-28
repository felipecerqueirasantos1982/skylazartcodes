/* 
   Private CGI Scan, Do Not Distribute!

   skycgiscan 0.1 beta
   by skylazart - Jun/2005
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>

long net_resolve (char *dn)
{
	long i;
	struct hostent *dnPtr;

	i = inet_addr (dn);
	if (i == -1) {
		dnPtr = gethostbyname (dn);
		if (!dnPtr) {
			return (0);
		} else {
			return (*(unsigned long *) dnPtr->h_addr);
		}
	}
	return (i);
}

int net_connect (char * dn, int p, int ttl)
{
	struct sockaddr_in sin;
	struct timeval tv;
	int fd;
	int n;
	int flags;
	fd_set wset;
	fd_set rset;
	int opt = 1024;		/* MAXCAPLEN */
	int one = 1;
	int err = 0;
	socklen_t dummy = sizeof (err);
	
	sin.sin_family = PF_INET;
	sin.sin_port = htons (p);
	if (!(sin.sin_addr.s_addr = net_resolve (dn)))
		return (0);
	memset (&(sin.sin_zero), 0, 8);
	
	if ((fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
                //avisa ae
                return (-1);
	}

	setsockopt (fd, SOL_SOCKET, SO_RCVBUF, (char *)&opt, sizeof (int));
	ioctl (fd, FIONBIO, &one);
	flags = fcntl (fd, F_GETFL, 0);
	fcntl (fd, F_SETFL, O_NONBLOCK | O_NDELAY);
	
	n = connect (fd, (struct sockaddr *)&sin, sizeof (sin));
	if (n == 0) {
		close (fd);
		goto done;
	}
	
	if (errno != EINPROGRESS) {
		close (fd);
		return (-1);
	}
	
	FD_ZERO (&wset);
	FD_ZERO (&rset);
	FD_SET (fd, &wset);
	FD_SET (fd, &rset);
	tv.tv_usec = 0;
	tv.tv_sec = ttl;
	
	if ((n = select (fd + 1, &rset, &wset, NULL, &tv)) == 0) {
		close (fd);
		errno = ETIMEDOUT;
		return (-1);
	}
	
	if (FD_ISSET (fd, &wset) || FD_ISSET (fd, &rset)) {
		if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &dummy)<0) {
			close (fd);
			return (-1);
		} else {
			if (err == 0) {
				goto done;
			} else {
				close (fd);
				return (-1);
			}
		}
	}
 done:
	n = 0;
	ioctl (fd, FIONBIO, &n);
	fcntl (fd, F_SETFL, flags);

	return (fd);	
}

int net_has_data (int fd, long ttl)
{
	struct timeval tv;
	fd_set rset;
	tv.tv_usec = 0;
	tv.tv_sec = ttl;
	FD_ZERO (&rset);
	FD_SET (fd, &rset);
	return (select (fd + 1, &rset, NULL, NULL, &tv));
}
