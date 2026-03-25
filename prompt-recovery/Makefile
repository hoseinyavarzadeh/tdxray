SRCS := $(wildcard *.cpp)
OBJS := $(SRCS:.cpp=.o)
CXXFLAGS = -I../tdxutils -I../include -Wall -Wextra -Wno-unused-function -Wno-unused-result -Os -std=c++23 -Wl,-rpath,. -g -flto

BINARIES := recover-prompt
recover-prompt_OBJS := recovery.o recover-prompt.o filters-llama.o filters-gemma.o llama-tokenizer.o

all: $(BINARIES)

$(BINARIES): $(OBJS)
	$(CXX) $(CXXFLAGS) $($@_OBJS) -o $@ -lllama

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(BINARIES) *.o
