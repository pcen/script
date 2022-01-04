DEBUG=NODEBUG

CXX = g++
CXXFLAGS = -std=c++17 -include config.h -g -D$(DEBUG)
LDFLAGS = -lutil

OBJ = main.o script.o ttyutils.o monotonic.o signames.o pty-session.o

script: $(OBJ)
	$(CXX) $(OBJ) -o script $(LDFLAGS) $(CXXFLAGS)

%.o: %.cc
	$(CXX) -c $< -o $@ $(CXXFLAGS)

.PHONY: clean
clean:
	-rm *.o *.txt script typescript
