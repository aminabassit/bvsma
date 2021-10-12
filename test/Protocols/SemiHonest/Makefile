CXX = /usr/bin/g++


CLIENTDATA = /home/obre/bvsma/data/client/
SERVERDATA = /home/obre/bvsma/data/server/


SRCFILES = $(wildcard /home/obre/bvsma/src/*.cpp)
OBJECTS = $(SRCFILES:.cpp=.o)

PREFLAGS = -g -fopenmp

CXXFLAGS = -I/home/obre/
CXXFLAGS += -std=c++14 
CXXFLAGS += /home/obre/libscapi/libscapi.a 
CXXFLAGS += -L/home/obre/boost_1_71_0/stage/lib 
CXXFLAGS += -ldl -lboost_log -lboost_serialization -lboost_filesystem -lssl -lcrypto -lgmp -lpthread -lboost_thread -lboost_system


client: $(OBJECTS)
	$(CXX) $(PREFLAGS) client.cpp -o $@ $^ $(CXXFLAGS)

server: $(OBJECTS)
	$(CXX) $(PREFLAGS) server.cpp -o $@ $^ $(CXXFLAGS)


.PHONY: clean-data
clean-data:
	find $(CLIENTDATA) -type d -name "user*" -exec rm -rv {} +
	find $(CLIENTDATA) -type f -name "*.csv" -delete
	find $(SERVERDATA) -type d -name "user*" -exec rm -rv {} +
	find $(SERVERDATA) -type f -name "*.csv" -delete

.PHONY: clean
clean:
	rm -f $(OBJECTS) client
	rm -f $(OBJECTS) server
	rm -f *.o