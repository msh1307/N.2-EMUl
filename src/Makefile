CC=gcc                         
OBJS=main.o util.o elf.o
TARGET=app.out                  
FLAGS=-lunicorn -lpthread -lm -lelf

$(TARGET): $(OBJS) 
	$(CC) -o $@ $(OBJS) $(FLAGS)

main.o: main.c util.o elf.o

elf.o: elf.c util.o

util.o: util.c


all: $(TARGET)

clean:
	rm -f *.o                         
	rm -f $(TARGET)
