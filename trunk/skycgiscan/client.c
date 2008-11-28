#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "fila.h"
#include "mask.h"
#include "skycgiscan.h"

void stdin_scanner (Fila_t * fila)
{
	char buf[256];
	
	while (fgets (buf, sizeof (buf)-1, stdin)) {
		buf[strlen (buf)-1] = '\0';
		strncpy (fila->data.buf, buf, sizeof (fila->data.buf));
		envia_fila (fila);
	}
	exit (0);
}

int main (int argc, char ** argv)
{
	Fila_t fila;
	
	printf ("skyCGI scanner\n"
		"by skylazart - Jun/2005\n"
		"Private, do not distribute\n\n");

	if (!argv[1]) {
		printf ("%s <network>\n", argv[0]); 
		exit (0);
	}

	abre_fila (&fila);

	if (argv[1][0] == '-') {
		printf ("Waiting data from stdin...\n");
		stdin_scanner (&fila);
	}

	mask_init (argv[1]);

	for (;;) {
		if (!mask_get_next (fila.data.buf, sizeof (fila.data.buf)-1))
			break;		
		envia_fila (&fila);
	}
}
