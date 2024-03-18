CC=gcc                         
OBJS=main.o 
TARGET=app.out                  
FLAGS=-lunicorn -lpthread -lm 

$(TARGET): $(OBJS) 
	$(CC) -o $@ $(OBJS) $(FLAGS)

main.o: main.c

all: $(TARGET)

clean:
	rm -f *.o                         
	rm -f $(TARGET)
