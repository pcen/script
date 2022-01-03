CXX = g++
CFLAGS = -include config.h -g
LDFLAGS = -lutil

OBJ = ttyutils.o timeutils.o monotonic.o signames.o strutils.o pty-session.o

script: script.o $(OBJ)
	$(CXX) script.o $(OBJ) -o script $(LDFLAGS)

%.o: %.cc
	$(CXX) -c $< -o $@ $(CFLAGS)

.PHONY: clean
clean:
	-rm *.o script typescript
