CC		= gcc
CFLAGS	= -Wall -02 -I./include
LFLAGS	= -lpcap
SRC		= src/main.c src/rules.c src/logger.c src/anomaly.c
TARGET	= SimpleIDS

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

clean:
	rm -f $(TARGET)

run: all
	sudo ./$(TARGET)