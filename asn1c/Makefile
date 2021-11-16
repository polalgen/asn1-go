CC=gcc
CFLAGS=-I.
TARGET=../rectangle.lib
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)

ifeq ($(OS),Windows_NT)
	RM=del
endif

# copy all .o object code to ../s1ap.a static library 
all:$(OBJECTS)
	ar rcs $(TARGET) $(OBJECTS)

# compile all .c files to .o objects 
$(OBJECTS): %.o: %.c
	$(CC) -c $(CFLAGS)  $< -o $@

clean:
	$(RM) $(OBJECTS)

# regenerate c code with asn1c compiler
regen:
	asn1c  -gen-PER -fcompound-names -S ../skeletons ../asn1/*
	$(RM) converter-sample.c