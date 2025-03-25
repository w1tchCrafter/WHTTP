CFLAGS := -Wall -fPIC -lssl -lcrypto
LDFLAGS := -shared
TARGET := libwhttp.so
SRC := src/common.c src/wnet.c src/whttp.c
INCLUDES := include/*
OBJ := ${SRC:.c=.o}
CC := gcc
PREFIX := /usr


all: ${TARGET}

${TARGET}: ${OBJ}
	${CC} ${LDFLAGS} -o ${TARGET} ${OBJ}

%.o: %.c 
	${CC} ${CFLAGS} -c $< -o $@
clean:
	@rm -rf *.o src/*.o ${TARGET}

install: ${TARGET}
	@echo "Installing ${TARGET} to ${PREFIX}/lib"
	@cp ${TARGET} ${PREFIX}/lib
	@cp ${INCLUDES} /usr/include
	@ldconfig

ininstall:
	@echo "Removing ${TARGET} from ${PREFIX}/lib"
	@rm -f ${PREFIX}/lib/${TARGET}
	@ldconfig