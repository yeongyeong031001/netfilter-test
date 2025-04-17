# Makefile

TARGET = netfilter-test
SRC = netfilter-test.c
CC = gcc
CFLAGS = -g -Wall
LIBS = -lnetfilter_queue

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

