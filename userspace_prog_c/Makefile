CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDLIBS = -lnftables
SRCS = packet_handler.cc decision_tree.cc flow_tracker.cc
OBJS = $(SRCS:.cc=.o)
TARGET = packet_handler

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
