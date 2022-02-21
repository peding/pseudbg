PROGRAM := ./pseudbg.so

CC := gcc
CFLAGS := -shared -fPIC -Wall -Wextra -std=c99
LDFLAGS := -ldl -lcapstone

.PHONY: program clean

program: $(PROGRAM)

$(PROGRAM): *.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(PROGRAM)
