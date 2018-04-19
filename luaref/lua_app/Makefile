ARMCC ?= gcc
LUALIB ?= ../../luacopy
CFLAGS = -std=gnu99 -O2 -Wall -Wcast-align -Wsuggest-attribute=noreturn \
		 -Wfloat-equal -Wswitch-default -Wformat-nonliteral -Wextra \
		 -I$(LUALIB)


TARGET = lua_program
OBJECTS = main.o lua_helpers.o fakeoptee.o capsule_lua_ext.o test_driver.o 
LIBS = $(LUALIB)/refbuild/liblua.a

%.o: %.c
	$(ARMCC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS) $(LIBS)
	$(ARMCC) $(OBJECTS) $(LIBS) $(CFLAGS) -o $@

default: $(TARGET)

clean:
	-rm -f $(TARGET)
	-rm -f *.o

