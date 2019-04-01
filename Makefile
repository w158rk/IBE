rm_dir = rm -rf
mv_command = mv
cmake_args = 
add_lib = 

ifeq ($(OS),Windows_NT)
	rm_dir = rd /s /q
	mv_command = move
	cmake_args = -G "MinGW Makefiles"
	add_lib = src/Library/pbc.dll
endif

lib : CMakeLists.txt $(add_lib)
	mkdir build && cd build && cmake $(cmake_args) ../ && make
	$(move) $(add_lib) build/	


clean:
	$(rm_dir) build 
