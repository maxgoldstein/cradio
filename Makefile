CPP = gcc
COMPILERFLAGS = -g -Wall -Wextra
LINKLIBS = -lpcap
CRADIOOBJECTS = obj/cradio.o

.PHONY: all clean

all : obj cradio

cradio : $(CRADIOOBJECTS)
	$(CPP) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)

clean :
	$(RM) obj/*.o cradio

obj/%.o: src/%.c
	$(CPP) $(COMPILERFLAGS) $(LINKLIBS) -c -o $@ $<
obj:
	mkdir -p obj

