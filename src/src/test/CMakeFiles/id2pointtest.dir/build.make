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
include src/test/CMakeFiles/id2pointtest.dir/depend.make

# Include the progress variables for this target.
include src/test/CMakeFiles/id2pointtest.dir/progress.make

# Include the compile flags for this target's objects.
include src/test/CMakeFiles/id2pointtest.dir/flags.make

src/test/CMakeFiles/id2pointtest.dir/id2pointtest.c.o: src/test/CMakeFiles/id2pointtest.dir/flags.make
src/test/CMakeFiles/id2pointtest.dir/id2pointtest.c.o: test/id2pointtest.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wxy/work/IBE/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/test/CMakeFiles/id2pointtest.dir/id2pointtest.c.o"
	cd /home/wxy/work/IBE/src/src/test && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/id2pointtest.dir/id2pointtest.c.o   -c /home/wxy/work/IBE/src/test/id2pointtest.c

src/test/CMakeFiles/id2pointtest.dir/id2pointtest.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/id2pointtest.dir/id2pointtest.c.i"
	cd /home/wxy/work/IBE/src/src/test && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/wxy/work/IBE/src/test/id2pointtest.c > CMakeFiles/id2pointtest.dir/id2pointtest.c.i

src/test/CMakeFiles/id2pointtest.dir/id2pointtest.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/id2pointtest.dir/id2pointtest.c.s"
	cd /home/wxy/work/IBE/src/src/test && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/wxy/work/IBE/src/test/id2pointtest.c -o CMakeFiles/id2pointtest.dir/id2pointtest.c.s

# Object files for target id2pointtest
id2pointtest_OBJECTS = \
"CMakeFiles/id2pointtest.dir/id2pointtest.c.o"

# External object files for target id2pointtest
id2pointtest_EXTERNAL_OBJECTS =

bin/id2pointtest: src/test/CMakeFiles/id2pointtest.dir/id2pointtest.c.o
bin/id2pointtest: src/test/CMakeFiles/id2pointtest.dir/build.make
bin/id2pointtest: src/libibe.a
bin/id2pointtest: src/test/CMakeFiles/id2pointtest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wxy/work/IBE/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../bin/id2pointtest"
	cd /home/wxy/work/IBE/src/src/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/id2pointtest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/test/CMakeFiles/id2pointtest.dir/build: bin/id2pointtest

.PHONY : src/test/CMakeFiles/id2pointtest.dir/build

src/test/CMakeFiles/id2pointtest.dir/clean:
	cd /home/wxy/work/IBE/src/src/test && $(CMAKE_COMMAND) -P CMakeFiles/id2pointtest.dir/cmake_clean.cmake
.PHONY : src/test/CMakeFiles/id2pointtest.dir/clean

src/test/CMakeFiles/id2pointtest.dir/depend:
	cd /home/wxy/work/IBE/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wxy/work/IBE /home/wxy/work/IBE/src/test /home/wxy/work/IBE/src /home/wxy/work/IBE/src/src/test /home/wxy/work/IBE/src/src/test/CMakeFiles/id2pointtest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/test/CMakeFiles/id2pointtest.dir/depend

