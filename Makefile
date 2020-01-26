
CC = gcc
LD = gcc
CFLAGS = -Wall -ansi -Wextra -std=gnu11 -O2 \
	-I hacl-star/dist/gcc64-only \
	-I hacl-star/dist/kremlin/include/ \
	-I hacl-star/dist/kremlin/kremlib/dist/minimal
LDFLAGS = -O2

SRCS = test_inc_mac.c inc_mac.c
OBJS = $(subst .c,.o,$(SRCS))
OBJS += $(patsubst %.S,%.o,$(wildcard *.S))
EXEC = test_inc_mac

STATIC_LIBS = hacl-star/dist/gcc64-only/libevercrypt.a

all: $(EXEC) .depend

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.depend: $(SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^ >> ./.depend

-include .depend

$(EXEC): $(OBJS)
	$(LD) $(LDFLAGS) -o $(EXEC) $(OBJS) $(STATIC_LIBS)

clean:
	$(RM) $(EXEC) $(OBJS) .depend
