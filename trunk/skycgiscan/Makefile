LDLIBS=-lpthread
LDFLAGS=-Wall -g -ggdb

all: skycgiscan client

skycgiscan: skycgiscan.o utils.o net.o cgi.o fila.o mask.o
client: client.o utils.o net.o cgi.o fila.o mask.o

skycgiscan.o: skycgiscan.c skycgiscan.h
client.o: client.c
utils.o: utils.c
net.o: net.c net.h
cgi.o: cgi.c net.c net.h
fila.o: fila.c fila.h
mask.o: mask.c mask.h



clean:
	rm -rf *.o
	rm -rf client
	rm -rf skycgiscan
