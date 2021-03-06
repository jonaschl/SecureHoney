CC = gcc
CFLAGS = -g -Wall
CHMOD := $(shell which chmod)
SETCAP := $(shell which setcap)
USER := $(shell whoami)

all: sshpot

sshpot: main.o auth.o mysql-log.o
	$(CC) $(CFLAGS) $^ -lssh -lutil -ljansson -lmysqlclient -L/usr/lib64/mysql/ -lz -o $@

main.o: main.c config.h
	$(CC) $(CFLAGS) -c main.c

auth.o: auth.c auth.h config.h
	$(CC) $(CFLAGS)  -c auth.c

mysql-log.o: mysql-log.c auth.h config.h
		$(CC) $(CFLAGS) -I /usr/include/mysql  -c mysql-log.c

install:
	@if [ $(USER) != "root" ]; then echo make install must be run as root.; false; fi
	$(CHMOD) 755 sshpot
	$(SETCAP) 'cap_net_bind_service=+ep' sshpot

clean:
	\/bin/rm -f *.o
