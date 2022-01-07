DEBUG=NODEBUG

CXX = g++
CXXFLAGS = -std=c++17 -g -D$(DEBUG) -MMD
LDFLAGS = -lutil

OBJ = main.o script.o monitor.o ttyutils.o signames.o pty-session.o
DEPENDS = $(OBJ:.o=.d) # substitute ".o" with ".d"

.PHONY: clean clean-ts

script: $(OBJ)
	$(CXX) $(OBJ) -o script $(LDFLAGS) $(CXXFLAGS)

%.o: %.cc
	$(CXX) -c $< -o $@ $(CXXFLAGS)

-include $(DEPENDS)

clean:
	rm -f *.o *.d *.txt script typescript

clean-ts:
	rm -f *.txt typescript
