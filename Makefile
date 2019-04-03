rm_dir = rm -rf
mv_command = mv
cmake_args = 
lib_files = 

ifeq ($(OS),Windows_NT)
	rm_dir = rd /s /q
	mv_command = move
	cmake_args = -G "MinGW Makefiles"
	# lib_files = $(wildcard src/Library/WIN32/*)
endif

all : build CMakeLists.txt  # $(lib_files)
	cd build && cmake $(cmake_args) ../ && make

build:
	mkdir build 

clean:
	$(rm_dir) build 
	$(rm_dir) *_*
	$(rm_dir) *.conf

