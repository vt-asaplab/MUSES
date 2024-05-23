SECP256K1_LIB=/home/thanghoang/lib/lib/libsecp256k1.a
NTL_LIB=-L/home/thanghoang/lib/lib/
ZEROMQ_LIB=-L/usr/local/lib/
GMP_LIB=-L/usr/local/lib/
OPENSSL_LIB=-L/usr/local/lib/

DEPS=$(ZEROMQ_LIB) $(GMP_LIB) $(OPENSSL_LIB) $(SECP256K1_LIB) $(NTL_LIB)
LIBS=-lzmq -lgmp -lm -lcrypto -lntl -lgmp -lgmpxx 

Client: Client.cpp
	g++ *.cpp -o Client -I./ -I../ -I/home/thanghoang/lib/include -I../secp256k1_lib -I../emp_lib -I/usr/local/include -L/usr/local/lib -lzmq -lcrypto -pthread -Wall -funroll-loops -Wno-ignored-attributes -Wno-unused-result -march=native -maes -mavx2 -std=c++11 -O3 $(DEPS) $(LIBS)

clean:
	rm -f Client
