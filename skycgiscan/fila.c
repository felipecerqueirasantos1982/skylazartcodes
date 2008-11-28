#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#include "fila.h"

#define SYSVMODE ( S_IRWXU | S_IRWXU>>3 | S_IRWXU>>6 )
#define PROJECT_PATH "."
#define PROJECT_ID 0x52		/* nice ideia */

#define IPC_TIMEOUT 5

int abre_fila (Fila_t * fila)
{
	key_t key;
	
	key = ftok (PROJECT_PATH, PROJECT_ID);
	fila->msgfd = msgget (key, SYSVMODE | IPC_CREAT);
	return (fila->msgfd);	
}

int recebe_fila (Fila_t * fila)
{
	int n;
	time_t begin, now;

	fila->data.dummy = 0;

	time (&begin);
	do {
		n = msgrcv (fila->msgfd, &fila->data, sizeof (fila->data),0,0);
		if (n != -1) break;
		if (n == -1) {
			if (errno == EAGAIN) {
				time (&now);
				if ((now - begin) > IPC_TIMEOUT) break;
				continue;
			} else {
				break;
			}
		} 
	} while (1);
	return (n);
}

int envia_fila (Fila_t * fila)
{
	int n;
	time_t begin, now;

	fila->data.dummy = 0x1;

	time (&begin);
	do {
		n = msgsnd (fila->msgfd, &fila->data, sizeof (fila->data), 0);
		if (n != -1) break;
		if (n == -1) {
			if (errno == EAGAIN) {
				time (&now);
				if ((now - begin) > IPC_TIMEOUT) break;
				continue;
			} else {
				break;
			}
		}
	} while (1);
	return (n);
}

long fila_total (Fila_t * fila)
{
	int n;
	struct msqid_ds buf;

	n = msgctl (fila->msgfd, IPC_STAT, &buf);
	if (n == -1) return (n);

	return (buf.msg_qnum);
}
