CXX = g++
CXXFLAGS = -std=c++17 -include config.h -g
LDFLAGS = -lutil

OBJ = ttyutils.o monotonic.o signames.o pty-session.o

script: script.o $(OBJ)
	$(CXX) script.o $(OBJ) -o script $(LDFLAGS) $(CXXFLAGS)

%.o: %.cc
	$(CXX) -c $< -o $@ $(CXXFLAGS)

.PHONY: clean
clean:
	-rm *.o *.txt script typescript
