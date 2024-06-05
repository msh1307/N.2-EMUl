CC=gcc                         
OBJS=main.o util.o elf.o emul.o
TARGET=app.out                  
FLAGS=-lunicorn -lpthread -lm -lelf -lcapstone

$(TARGET): $(OBJS) 
	$(CC) -o $@ $(OBJS) $(FLAGS)

$(TARGET): $(OBJS)

main.o: main.c

elf.o: elf.c util.o

util.o: util.c

emul.o: emul.c

all: $(TARGET)

clean:
	rm -f *.o                         
	rm -f $(TARGET)
