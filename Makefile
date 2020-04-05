
CC = gcc
LD = gcc
CFLAGS = -Wall -ansi -Wextra -std=gnu11 -O2 \
	-I hacl-star/dist/gcc64-only \
	-I hacl-star/dist/kremlin/include/ \
	-I hacl-star/dist/kremlin/kremlib/dist/minimal
LDFLAGS = -O2

COMMON_SRCS = upd_mac.c

LIB_OBJS = $(subst .c,.o,$(COMMON_SRCS))
LIB_OBJS += ghash_register.o double_ghash_register.o
TEST_SRCS = test_upd_mac.c helpers.c nss.c
TEST_OBJS = $(subst .c,.o,$(TEST_SRCS))
TEST_OBJS += $(patsubst %.S,%.o,$(wildcard *.S))
TEST_EXEC = test_upd_mac

PROF_SRCS = profile.c helpers.c nss.c
PROF_OBJS = $(subst .c,.o,$(PROF_SRCS))
PROF_OBJS += $(patsubst %.S,%.o,$(wildcard *.S))
PROF_EXEC = profile

STATIC_LIBS = hacl-star/dist/gcc64-only/libevercrypt.a

RESULT_LIB = libupdmac.a

all: $(TEST_EXEC) $(PROF_EXEC) $(RESULT_LIB) .depend

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.depend: $(TEST_SRCS) $(PROF_SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^ >> ./.depend

-include .depend

$(RESULT_LIB): $(LIB_OBJS) $(STATIC_LIBS)
	$(AR) rcs $(RESULT_LIB) $(LIB_OBJS)

$(TEST_EXEC): $(TEST_OBJS) $(RESULT_LIB)
	$(LD) $(LDFLAGS) $(TEST_OBJS) $(RESULT_LIB) $(STATIC_LIBS) -o $(TEST_EXEC)

$(PROF_EXEC): $(PROF_OBJS) $(RESULT_LIB)
	$(LD) $(LDFLAGS) $(PROF_OBJS) $(RESULT_LIB) $(STATIC_LIBS) -lm -o $(PROF_EXEC)

clean:
	$(RM) $(TEST_EXEC) $(PROF_EXEC) $(RESULT_LIB) $(TEST_OBJS) $(PROF_OBJS) \
	$(LIB_OBJS) .depend
