# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/cmake-3.15.3/bin/cmake

# The command to remove a file.
RM = /opt/cmake-3.15.3/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/wxy/work/IBE

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/wxy/work/IBE/src

# Include any dependencies generated for this target.
include src/test/CMakeFiles/clienttest.dir/depend.make

# Include the progress variables for this target.
include src/test/CMakeFiles/clienttest.dir/progress.make

# Include the compile flags for this target's objects.
include src/test/CMakeFiles/clienttest.dir/flags.make

src/test/CMakeFiles/clienttest.dir/clienttest.cpp.o: src/test/CMakeFiles/clienttest.dir/flags.make
src/test/CMakeFiles/clienttest.dir/clienttest.cpp.o: test/clienttest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wxy/work/IBE/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/test/CMakeFiles/clienttest.dir/clienttest.cpp.o"
	cd /home/wxy/work/IBE/src/src/test && /usr/bin/g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/clienttest.dir/clienttest.cpp.o -c /home/wxy/work/IBE/src/test/clienttest.cpp

src/test/CMakeFiles/clienttest.dir/clienttest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/clienttest.dir/clienttest.cpp.i"
	cd /home/wxy/work/IBE/src/src/test && /usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/wxy/work/IBE/src/test/clienttest.cpp > CMakeFiles/clienttest.dir/clienttest.cpp.i

src/test/CMakeFiles/clienttest.dir/clienttest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/clienttest.dir/clienttest.cpp.s"
	cd /home/wxy/work/IBE/src/src/test && /usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/wxy/work/IBE/src/test/clienttest.cpp -o CMakeFiles/clienttest.dir/clienttest.cpp.s

# Object files for target clienttest
clienttest_OBJECTS = \
"CMakeFiles/clienttest.dir/clienttest.cpp.o"

# External object files for target clienttest
clienttest_EXTERNAL_OBJECTS =

bin/clienttest: src/test/CMakeFiles/clienttest.dir/clienttest.cpp.o
bin/clienttest: src/test/CMakeFiles/clienttest.dir/build.make
bin/clienttest: src/libibe.a
bin/clienttest: src/test/CMakeFiles/clienttest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wxy/work/IBE/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../bin/clienttest"
	cd /home/wxy/work/IBE/src/src/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/clienttest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/test/CMakeFiles/clienttest.dir/build: bin/clienttest

.PHONY : src/test/CMakeFiles/clienttest.dir/build

src/test/CMakeFiles/clienttest.dir/clean:
	cd /home/wxy/work/IBE/src/src/test && $(CMAKE_COMMAND) -P CMakeFiles/clienttest.dir/cmake_clean.cmake
.PHONY : src/test/CMakeFiles/clienttest.dir/clean

src/test/CMakeFiles/clienttest.dir/depend:
	cd /home/wxy/work/IBE/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wxy/work/IBE /home/wxy/work/IBE/src/test /home/wxy/work/IBE/src /home/wxy/work/IBE/src/src/test /home/wxy/work/IBE/src/src/test/CMakeFiles/clienttest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/test/CMakeFiles/clienttest.dir/depend

