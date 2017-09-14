LUA_SRC = ../../lua

CFLAGS = -std=gnu99 -O2 -Wall

default:
	gcc main.c $(LUA_SRC)/ltrusted_app.c -I$(LUA_SRC) \
		$(CFLAGS) -DTRUSTED_APP -o main_ta
	gcc main.c $(CFLAGS) -lm -o main_libc

clean:
	rm -f main_ta main_libc
