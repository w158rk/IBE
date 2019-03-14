
GTEST_DIR = /home/wrk/workspace/2019spring/IBE/src/gtest

# Where to find user code.
USER_DIR = /home/wrk/workspace/2019spring/IBE/src/BasicIdent_FullIdent


# Flags passed to the preprocessor.
CPPFLAGS += -I $(GTEST_DIR)/include

# Flags passed to the C++ compiler.
CXXFLAGS += -g -Wall -Wextra  -I /usr/local/include/  -L/usr/local/lib/ -L/usr/lib/x86_64-linux-gnu -Wl,-rpath /usr/local/lib -lpbc -lgmp



TESTS = bf_4_2_unittest


GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
				$(GTEST_DIR)/include/gtest/internal/*.h

# House-keeping build targets.

all : $(TESTS)

clean :
	echo $(GTEST_DIR)
	echo $(pwd)
	rm -f $(TESTS) gtest.a gtest_main.a *.o

# Builds gtest.a and gtest_main.a.


GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

utils.o:$(USER_DIR)/utils.h $(USER_DIR)/utils.c $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(USER_DIR)/utils.c

sha1.o: $(USER_DIR)/sha1.h $(USER_DIR)/sha1.c $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(USER_DIR)/sha1.c

bf_4_2.o : $(USER_DIR)/bf_4_2.c $(USER_DIR)/bf_4_2.h sha1.o  $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(USER_DIR)/bf_4_2.c 

bf_4_2_unittest.o : $(USER_DIR)/bf_4_2_unittest.c $(USER_DIR)/bf_4_2.h $(GTEST_HEADERS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(USER_DIR)/bf_4_2_unittest.c

bf_4_2_unittest : bf_4_2_unittest.o bf_4_2.o sha1.o utils.o gtest_main.a
	$(CXX) $(CPPFLAGS) $^ $(CXXFLAGS) -lpthread -o $@
