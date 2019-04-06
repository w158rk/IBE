rm_dir = rm -rf
rm_file = rm 
mv_command = mv
cmake_args = 
lib_files = 

ifeq ($(OS),Windows_NT)
	rm_dir = rd /s /q
	mv_command = move
	cmake_args = -G "MinGW Makefiles"
	rm_file = del 
	# lib_files = $(wildcard src/Library/WIN32/*)
endif

all : build CMakeLists.txt  # $(lib_files)
	cd build && cmake $(cmake_args) ../ && make

build:
	mkdir build 

clean:
	$(rm_dir) build 
	$(rm_file) *.conf
	$(rm_file) *_*

