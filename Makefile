CC=gcc
SRCS=./src/main.c ./src/util.c ./src/elf.c ./src/emul.c ./src/syscalls.c
OBJS=$(SRCS:.c=.o)
TARGET=app.out
FLAGS=-lunicorn -lpthread -lm -lelf -lcapstone

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(FLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(TARGET)

clean:
	rm -f ./src/*.o
	rm -f $(TARGET)