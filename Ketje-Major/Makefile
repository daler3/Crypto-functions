rm=/bin/rm -f
CC=cc
DEFS=
INCLUDES=-I.
LIBS=

DEFINES= $(INCLUDES) $(DEFS)
CFLAGS= -std=c99 $(DEFINES) -O2 -fomit-frame-pointer -funroll-loops -g -Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Wmissing-prototypes -Wformat=2 -Wcast-align -Wbad-function-cast -Wundef -Wunreachable-code -Wlogical-op -Wfloat-equal -Wold-style-definition

all: ketje_driver

ketje_driver: ketje_driver.c ketje.c ketje.h keccak.c keccak.h
	$(CC) $(CFLAGS) -o ketje_driver ketje_driver.c ketje.c keccak.c $(LIBS)

clean:
	$(rm) ketje.o keccak.o ketje_driver *.o core *~
