/* 
   Private CGI Scan, Do Not Distribute!

   skycgiscan 0.1 beta
   by skylazart - Jun/2005
*/

/*
  TODO:
  There is a long list...  

  [x] nmap like parsing (eg: 200.100-255.*.*)
  [x] varios cgis por conexao
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>


#include "fila.h"
#include "skycgiscan.h"

void create_threads (int tot, void * f, void *cgilist)
{
        int i;
        pthread_t tid;
        
        for (i = 0; i < tot; i++) {
                pthread_create (&tid, NULL, f, cgilist);
                pthread_detach (tid);
        }
}

void scan (char *cgilist)
{
	Fila_t fila;
	int n;
	char res[1024];
        char *buf, *data, *cgi;

	abre_fila (&fila);
	
	for (;;) {
		n = recebe_fila (&fila);
		if (n <= 0) continue;		
                
		printf ("\rScanning %.32s...\n", fila.data.buf);
                
		if (http_header (fila.data.buf, res, sizeof (res)) == 1) {
                        if(http_cgi(fila.data.buf,"/cgi-bin/fake.cgi")==200) {
				continue;
			}

                        buf = malloc (strlen (cgilist));
                        memcpy (buf, cgilist, strlen (cgilist));
                        cgi = strtok_r (buf, "\n", &data);
                        
                        while (cgi != NULL) {
                                http_cgi (fila.data.buf, cgi);
                                cgi = strtok_r (NULL, "\n", &data);
                        }
                        free (buf);
		}
	} 
}

void * thread_consumer (void * arg) 
{
	for (;;) {
		scan ((char*)arg);
	}
        
	pthread_exit (NULL);
}

char *open_cgi_list(char *filepath) 
{
        struct stat fd_info;
        char *cgilist; 
        int fd;
        
        fd = open (filepath, O_RDONLY);
        if (fd == -1) {
                perror ("open()"); 
                exit (1);
        }

        if (fstat (fd, &fd_info) == -1) {
                perror ("fstat()"); 
                exit (1);
        }

        cgilist = mmap (NULL, fd_info.st_size+4, PROT_READ, MAP_SHARED, fd, 0);
        if (cgilist == MAP_FAILED) {
                perror ("mmap()"); 
                exit (1);
        }
        
        return cgilist;
}

int main (int argc, char ** argv)
{
        char *cgilist;

	printf ("skyCGI scanner\n"
		"by skylazart - Jun/2005\n"
		"Private, do not distribute\n\n");

        if (argc != 2) {
                fprintf (stderr, "%s <cgi-list>\n", argv[0]);
                exit (1);
        } 

        cgilist = open_cgi_list(argv[1]);        
	create_threads (100, thread_consumer, cgilist);

	while (1) {
		pause ();
	}

	return (0);
}
