# This Makefile is based on LuaSec's Makefile. Thanks to the LuaSec developers.
# # Inform the location to intall the modules
LUAPATH  ?= /usr/local/share/lua/5.1
LUACPATH ?= /usr/local/lib/
INCDIR   ?= -I /usr/include/lua5.1
LIBDIR   ?= -lssl
CMOD = baselib.so
OBJS = baselib.c
LNX_CFLAGS  = -fPIC -shared -o
CC = gcc
LD = $(MYENV) gcc

.PHONY: all clean install uninstall

all: $(CMOD)

install: $(CMOD)
	cp $(CMOD) $(LUACPATH)
uninstall:
	rm $(LUACPATH)/$(CMOD)

clean:
	rm -f $(CMOD)
.c.o:
	$(cc) $(OBJS) $(LNX_CFLAGS) $(CMOD) $(INCDIR) $(LIBDIR)$@ $<

$(CMOD): $(OBJS)
	$(LD) $(OBJS) $(LNX_CFLAGS) $(CMOD) $(INCDIR) $(LIBDIR)	
