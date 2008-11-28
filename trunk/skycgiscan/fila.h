#ifndef __FILA_H__
#define __FILA_H__

struct fila_data_t {
	long dummy;
	char buf[255];
};
typedef struct fila_data_t FilaData_t;

struct fila_t {
	int msgfd;
	FilaData_t data;
};
typedef struct fila_t Fila_t;

extern int abre_fila ();
extern int recebe_fila ();
extern int envia_fila ();
extern long fila_total ();

#endif /* __FILA_H__ */
