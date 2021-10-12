CXX = /usr/bin/g++


SRCFILES = $(wildcard /home/obre/bvsma/src/*.cpp)
OBJECTS = $(SRCFILES:.cpp=.o)

PREFLAGS = -g -fopenmp

CXXFLAGS = -I/home/obre/
CXXFLAGS += -std=c++14 
CXXFLAGS += /home/obre/libscapi/libscapi.a 
CXXFLAGS += -L/home/obre/boost_1_71_0/stage/lib 
CXXFLAGS += -ldl -lboost_log -lboost_serialization -lboost_filesystem -lssl -lcrypto -lgmp -lpthread -lboost_thread -lboost_system


prover: $(OBJECTS)
	$(CXX) $(PREFLAGS) prover.cpp -o $@ $^ $(CXXFLAGS)

verifier: $(OBJECTS)
	$(CXX) $(PREFLAGS) verifier.cpp -o $@ $^ $(CXXFLAGS)

proverParallel: $(OBJECTS)
	$(CXX) $(PREFLAGS) proverParallel.cpp -o $@ $^ $(CXXFLAGS)

verifierParallel: $(OBJECTS)
	$(CXX) $(PREFLAGS) verifierParallel.cpp -o $@ $^ $(CXXFLAGS)


.PHONY: clean
clean:
	rm -f $(OBJECTS) prover
	rm -f $(OBJECTS) verifier
	rm -f $(OBJECTS) proverParallel
	rm -f $(OBJECTS) verifierParallel
	rm -f *.o