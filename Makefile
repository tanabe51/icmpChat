PROGRAM=chat
OBJS=main.o ether.o checksum.o ip.o icmp.o packetAnalyze.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -lpthread
LDFLAGS=-pthread
$(PROGRAM):$(OBJS)
	 $(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
