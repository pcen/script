CC = gcc
CFLAGS = -include config.h
LDFLAGS = -lutil

OBJ = ttyutils.o timeutils.o monotonic.o signames.o strutils.o pty-session.o

script: script.o $(OBJ)
	$(CC) script.o $(OBJ) -o script $(LDFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

.PHONY: clean
clean:
	rm *.o script typescript
