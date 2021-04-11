CC := gcc
CFLAGS := -Wall -O3
LDLIBS := -lpthread

TARGET := sfmount
MAIN := driver.o
OBJ := util.o log.o sffs.o $(MAIN)
DEPS := driver.h sffs.h log.h util.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -g `pkg-config fuse --cflags --libs` -D_FILE_OFFSET_BITS=64 $(CFLAGS) $(LDLIBS) $^ -o $(TARGET)

util.o: %.o : %.c util.h
	$(CC) $(CFLAGS) $(LDLIBS) -c $<

log.o: %.o : %.c log.h
	$(CC) $(CFLAGS) -c $<

sffs.o: %.o : %.c sffs.h
	$(CC) $(CFLAGS) $(LDLIBS) -c $<

$(MAIN): %.o : %.c $(DEPS)
	$(CC) -g `pkg-config fuse --cflags --libs` -D_FILE_OFFSET_BITS=64 $(CFLAGS) $(LDLIBS) -c $<

clean:
	rm -r $(TARGET) $(OBJ)
