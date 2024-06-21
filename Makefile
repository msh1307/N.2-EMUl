CC=gcc
SRCS=./src/main.c ./src/util.c ./src/elf.c ./src/emul.c ./src/syscalls.c ./src/user_defined_hooks.c
OBJS=$(SRCS:.c=.o)
TARGET=app.out
FLAGS=-lunicorn -lpthread -lm -lelf -lcapstone
TEST_SRCS = tests/test.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(FLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(TARGET)

test: $(TARGET) $(TEST_OBJS)
	$(CC) $(CFLAGS) $(TEST_OBJS) -o ./vfs/test.out
	./$(TARGET) ./vfs /test.out

clean:
	rm -f ./src/*.o
	rm -f $(TARGET)
	rm -f ./tests/*.o
	rm -f ./*.out
	rm -f ./vfs/test.out