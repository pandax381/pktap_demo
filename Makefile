PROGRAM = pktap_demo

OBJECTS = 

CFLAGS  := $(CFLAGS) -g -W -Wall -DPRIVATE

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(PROGRAM)

$(PROGRAM): % : %.o $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(PROGRAM) $(PROGRAM:=.o) $(OBJECTS)
