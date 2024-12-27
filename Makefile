NDHS_C_SRCS = $(sort attach_bpf.c cfg.c dhcp4.c dhcp6.c dhcp_state.c duid.c dynlease.c multicast6.c nl.c nlsocket.c options.c radv6.c nk/hwrng.c nk/random.c nk/io.c nk/privs.c)
NDHS_CXX_SRCS = $(sort ndhs.cpp)
NDHS_OBJS = $(NDHS_C_SRCS:.c=.o) $(NDHS_CXX_SRCS:.cpp=.o)
NDHS_DEP = $(NDHS_C_SRCS:.c=.d) $(NDHS_CXX_SRCS:.cpp=.d)
INCL = -I.

CFLAGS = -MMD -Os -s -flto -std=gnu99 -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -Wno-discarded-qualifiers -Wstrict-overflow=5 -DNDHS_BUILD
CXXFLAGS = -MMD -Os -s -flto -std=gnu++20 -fno-rtti -fno-exceptions -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wsign-conversion -Wstrict-overflow=5 -DNDHS_BUILD
#CFLAGS = -MMD -Og -g -std=gnu99 -fsanitize=address,undefined -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -Wno-discarded-qualifiers -Wstrict-overflow=5 -DNDHS_BUILD
#CXXFLAGS = -MMD -Og -g -std=gnu++20 -fsanitize=address,undefined -fno-rtti -fno-exceptions -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wsign-conversion -Wstrict-overflow=5 -DNDHS_BUILD
CPPFLAGS += $(INCL)

all: ragel ndhs

ndhs: $(NDHS_OBJS)
	$(CXX) $(CXXFLAGS) $(INCL) -o $@ $^

-include $(NDHS_DEP)

clean:
	rm -f $(NDHS_OBJS) $(NDHS_DEP) ndhs

cleanragel:
	rm -f dynlease.c cfg.c

dynlease.c: dynlease.rl
	ragel -G2 -o dynlease.c dynlease.rl

cfg.c: cfg.rl
	ragel -T0 -o cfg.c cfg.rl

ragel: dynlease.c cfg.c

.PHONY: all clean cleanragel

