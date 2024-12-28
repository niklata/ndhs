NDHS_C_SRCS = $(sort attach_bpf.c cfg.c dhcp4.c dhcp6.c dhcp_state.c duid.c dynlease.c multicast6.c ndhs.c nl.c nlsocket.c options.c radv6.c nk/hwrng.c nk/random.c nk/io.c nk/privs.c)
NDHS_OBJS = $(NDHS_C_SRCS:.c=.o)
NDHS_DEP = $(NDHS_C_SRCS:.c=.d)
INCL = -I.

CFLAGS = -MMD -Os -s -flto -std=gnu99 -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -Wno-discarded-qualifiers -DNDHS_BUILD
#CFLAGS = -MMD -Og -g -std=gnu99 -fsanitize=address,undefined -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -Wno-discarded-qualifiers -DNDHS_BUILD
CPPFLAGS += $(INCL)

all: ragel ndhs

ndhs: $(NDHS_OBJS)
	$(CC) $(CFLAGS) $(INCL) -o $@ $^

-include $(NDHS_DEP)

clean:
	rm -f $(NDHS_OBJS) $(NDHS_DEP) ndhs

cleanragel:
	rm -f dynlease.c cfg.c

dynlease.c: dynlease.rl
	ragel -T0 -o dynlease.c dynlease.rl

cfg.c: cfg.rl
	ragel -T0 -o cfg.c cfg.rl

ragel: dynlease.c cfg.c

.PHONY: all clean cleanragel

