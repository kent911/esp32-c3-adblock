CXX      ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -O1 -g -fsanitize=address,undefined
BIN      := build/test_dns_core

.PHONY: test clean
test: $(BIN)
	./$(BIN)

$(BIN): native/test_dns_core.cpp native/test_util.h ../src/dns_core.h
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -o $@ native/test_dns_core.cpp

clean:
	rm -rf build
