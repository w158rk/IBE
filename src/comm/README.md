Railway-ticket-system
==============
	Home work of Linux System Programming. Focus on IPC, socket programming, and FIFO
	This railway ticket system has two version: a FIFO version and a socket version
	Thanks to (almost) everything is a file in Unix and Linux, which makes it much easier for me to write these two versions

##INSTALL
	To run this program you need the mysql server and client. You also need the curses library.
	To prepare the database, you just need to run the database.sql
	In the Makefile, you can know where the mysql client and curses share object expected to be. If your share objects are in different place, you can change the Makefile and recompile it.

##DESIGN
	Because everything is a file, I treat FIFO and socket equally in the program with some exception.
	The way to connect server and client is different between FIFO version and socket version. But after connection, I get two FILE pointer, one represents for read end and another represents for write end(FIFO is half-duplex so we need two FILE pointer, in the socket version these two pointer are just same), so client and server use these two pointer to communicate with each other(they don't need to know whether the FILE is a socket or FIFO, everything is a file!).
	All the core functions of the program are in client_core.c and server_core.c respectively. In these two files, only file, no concept of socket or FIFO.

##EXPERIENCE
	1. When you write Makefile, you should write header files in prerequisites for a given target. Becuse if you don't do that, when you change the header file only(may modify a define), make won't recompile the file(it still thinks everything is new).
	2. I asked a question in stackoverflow: http://stackoverflow.com/questions/9545039/linux-socket-programming-with-the-consideration-of-real-size-of-char
	3. Wrap the read and write functions because in the socket programming, every read or write may fail and you need to check the various exception conditions.
	4. When debuging with print, you should always add a '\n' to flush the buffer
	5. Some functions may not clear errno, you should care about that
	6. Always check errno or return value after system call or library function call
