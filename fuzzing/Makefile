TARGET=Fuzzer

#EXEFuzzer
FUZZSTUN=FuzzStun
FUZZSTUNCLIENT=FuzzStunClient

#Tag
SET=cd ../ &&
EXTCFLAGS= -Wall -Wextra
TAG=-DLIBEV_OK -DTURN_HAS_DAEMON -DTURN_NO_PROMETHEUS
INC=-I../src -I../src/apps/common -I../src/server -I../src/client -I../src/client++ 
LIBINC=-L../lib/ -lturnclient
LIB=$(LIBINC) -lssl -lcrypto
stun_buffer=../src/apps/common/stun_buffer.c


all: $(TARGET)

CONF:
	$(SET) CC=$(CC) CFLAGS="$(CFLAGS)" LDFLAGS="$(CFLAGS)" ./configure 
MAKEALL:
	$(SET) make all 

$(TARGET): CONF MAKEALL
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(TAG) $(INC) -c $(FUZZSTUN).c
	$(CXX) $(CFLAGS) $(LIB_FUZZING_ENGINE) $(FUZZSTUN).o -o $(FUZZSTUN) $(LIB)

	$(CC) $(EXTCFLAGS) $(CFLAGS) $(TAG) $(INC) -c $(FUZZSTUNCLIENT).c
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(TAG) $(INC) -c $(stun_buffer)
	$(CXX) $(CFLAGS) $(LIB_FUZZING_ENGINE) $(FUZZSTUNCLIENT).o stun_buffer.o -o $(FUZZSTUNCLIENT) $(LIB)

clean:
	rm $(FUZZSTUN) $(FUZZSTUNCLIENT) *.o

reallyclean: clean
	$(SET) make clean

.PHONY: all clean reallyclean
