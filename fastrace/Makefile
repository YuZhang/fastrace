# makefile 
#          -- for `fastrace'
# Author: zhangyu @pact518.hit.edu.cn
# Date: 2004-4-13

SHELL := /bin/sh

SRCPATH := .
BINPATH := /usr/local/bin
MANPATH := /usr/local/man/man6
TESTPATH := .
INCPATH := .
SOURCE := $(wildcard $(SRCPATH)/*.c)
OBJS := $(patsubst %.c,%.o,$(SOURCE))

EXECUTABLE := fastrace 
MANUAL := fastrace.6
PACKAGE := fastrace 
VERSION := 0.1.0
CC := gcc
CFLAGS := -Wall -g -I$(INCPATH)

.PHONY : all deps objs clean rebuild install

all : $(EXECUTABLE)

deps : $(DEPS)

objs : $(OBJS)

clean :
	rm -f $(OBJS)
	rm -f $(EXECUTABLE)

rebuild : clean all

# To install things in the right place
install: $(EXECUTABLE) 
	cp -f $(EXECUTABLE) $(BINPATH)
	cp -f $(MANUAL) $(MANPATH)

$(EXECUTABLE) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

