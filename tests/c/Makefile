CC = gcc
FLAGS = -std=c99 -L/usr/local/lib -I/usr/local/include -largon2
RUN = test

build:
	@$(CC) $(FLAGS) $(RUN).c -o $(RUN);

run:
	@$(CC) $(FLAGS) $(RUN).c -o $(RUN); ./$(RUN);

valgrind:
	@$(CC) $(FLAGS) $(RUN).c -o $(RUN); valgrind $(RUN);
