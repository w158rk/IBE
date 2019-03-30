lib : clean
	mkdir build && cd build && cmake ../src/ && make

clean:
	rm build -rf	