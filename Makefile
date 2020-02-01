
CC = gcc
LD = gcc
CFLAGS = -Wall -ansi -Wextra -std=gnu11 -O2 \
	-I hacl-star/dist/gcc64-only \
	-I hacl-star/dist/kremlin/include/ \
	-I hacl-star/dist/kremlin/kremlib/dist/minimal
LDFLAGS = -O2

COMMON_SRCS = inc_mac.c

TEST_SRCS = test_inc_mac.c helpers.c
TEST_SRCS += $(COMMON_SRCS)
TEST_OBJS = $(subst .c,.o,$(TEST_SRCS))
TEST_OBJS += $(patsubst %.S,%.o,$(wildcard *.S))
TEST_EXEC = test_inc_mac

PROF_SRCS = profile.c helpers.c
PROF_SRCS += $(COMMON_SRCS)
PROF_OBJS = $(subst .c,.o,$(PROF_SRCS))
PROF_OBJS += $(patsubst %.S,%.o,$(wildcard *.S))
PROF_EXEC = profile

STATIC_LIBS = hacl-star/dist/gcc64-only/libevercrypt.a

all: $(TEST_EXEC) $(PROF_EXEC) .depend

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.depend: $(TEST_SRCS) $(PROF_SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^ >> ./.depend

-include .depend

$(TEST_EXEC): $(TEST_OBJS)
	$(LD) $(LDFLAGS) $(TEST_OBJS) $(STATIC_LIBS) -o $(TEST_EXEC)

$(PROF_EXEC): $(PROF_OBJS)
	$(LD) $(LDFLAGS) $(PROF_OBJS) $(STATIC_LIBS) -o $(PROF_EXEC)

clean:
	$(RM) $(EXEC) $(TEST_OBJS) $(PROF_OBJS) .depend
