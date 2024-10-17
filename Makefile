#Compiler and flags
CC = gcc
CFLAGS = -Wall -g

#Necessary Libs
ECDH_LIBS = -lsodium
RSA_LIBS = -lgmp

#Executables
ECDH_EXEC = ecdh_assign_1
RSA_EXEC = rsa_assign_1

#Source files
ECDH_SRC = ECDH.c
RSA_SRC = RSA.c

#Object files
ECDH_OBJ = ECDH.o
RSA_OBJ = RSA.o

#Targets
all: $(ECDH_EXEC) $(RSA_EXEC)

#ECDH executable
$(ECDH_EXEC): $(ECDH_OBJ)
	$(CC) $(CFLAGS) -o $(ECDH_EXEC) $(ECDH_OBJ) $(ECDH_LIBS)

#RSA executable
$(RSA_EXEC): $(RSA_OBJ)
	$(CC) $(CFLAGS) -o $(RSA_EXEC) $(RSA_OBJ) $(RSA_LIBS)

#Compile ECDH object
$(ECDH_OBJ): $(ECDH_SRC)
	$(CC) $(CFLAGS) -c $(ECDH_SRC)

#Compile RSA object
$(RSA_OBJ): $(RSA_SRC)
	$(CC) $(CFLAGS) -c $(RSA_SRC)

#Clean up object files and executables
clean:
	rm -f $(ECDH_OBJ) $(RSA_OBJ) $(ECDH_EXEC) $(RSA_EXEC)

.PHONY: all clean