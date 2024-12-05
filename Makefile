NDHS_C_SRCS = $(sort attach_bpf.c nl.c options.c nk/hwrng.c nk/io.c nk/privs.c)
NDHS_CXX_SRCS = $(sort cfg.cpp dhcp4.cpp dhcp6.cpp dhcp_state.cpp duid.cpp dynlease.cpp ndhs.cpp nlsocket.cpp radv6.cpp rng.cpp nk/ip_address.cpp dynlease.cpp cfg.cpp)
NDHS_OBJS = $(NDHS_C_SRCS:.c=.o) $(NDHS_CXX_SRCS:.cpp=.o)
NDHS_DEP = $(NDHS_C_SRCS:.c=.d) $(NDHS_CXX_SRCS:.cpp=.d)
INCL = -I.

CFLAGS = -MMD -O2 -s -std=gnu99 -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -Wno-discarded-qualifiers -Wstrict-overflow=5 -DNDHS_BUILD
CXXFLAGS = -MMD -O2 -s -std=gnu++20 -fno-rtti -fno-exceptions -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wsign-conversion -Wstrict-overflow=5 -DNDHS_BUILD
CPPFLAGS += $(INCL)

all: ragel ndhs

ndhs: $(NDHS_OBJS)
	$(CXX) $(CXXFLAGS) $(INCL) -o $@ $^

-include $(NDHS_DEP)

clean:
	rm -f $(NDHS_OBJS) $(NDHS_DEP) ndhs

cleanragel:
	rm -f dynlease.cpp cfg.cpp

dynlease.cpp: dynlease.rl
	ragel -G2 -o dynlease.cpp dynlease.rl

cfg.cpp: cfg.rl
	ragel -T0 -o cfg.cpp cfg.rl

ragel: dynlease.cpp cfg.cpp

.PHONY: all clean cleanragel

