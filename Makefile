NDHS_C_SRCS = $(sort $(wildcard *.c) $(wildcard nk/*.c))
NDHS_CXX_SRCS = $(sort $(wildcard *.cpp) $(wildcard nk/*.cpp) dynlease.cpp cfg.cpp)
NDHS_OBJS = $(NDHS_C_SRCS:.c=.o) $(NDHS_CXX_SRCS:.cpp=.o)
NDHS_DEP = $(NDHS_C_SRCS:.c=.d) $(NDHS_CXX_SRCS:.cpp=.d)
INCL = -I.

CC ?= gcc
CCX ?= g++
CFLAGS = -MMD -O2 -s -fno-strict-overflow -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wcast-qual -Wsign-conversion -DNDHS_BUILD
CXXFLAGS = -MMD -O2 -s -std=gnu++17 -fno-strict-overflow -fno-rtti -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat-security -Wpointer-arith -DNDHS_BUILD

-include $(NDHS_DEP)

all: ragel ndhs

clean:
	rm -f $(NDHS_OBJS) $(NDHS_DEP) ndhs

cleanragel:
	rm -f dynlease.cpp cfg.cpp

dynlease.cpp:
	ragel -G2 -o dynlease.cpp dynlease.rl

cfg.cpp:
	ragel -G2 -o cfg.cpp cfg.rl

ragel: dynlease.cpp cfg.cpp

%.o: %.c
	$(CC) $(CFLAGS) $(INCL) -c -o $@ $^

%.o: %.cpp
	$(CCX) $(CXXFLAGS) $(INCL) -c -o $@ $^

ndhs: $(NDHS_OBJS)
	$(CCX) $(CXXFLAGS) $(INCL) -o $@ $^

.PHONY: all clean cleanragel
