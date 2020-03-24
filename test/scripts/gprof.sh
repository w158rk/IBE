 
#!/bin/bash

BINDIR=bin
OUTDIR=./data
app=$1
note=$2
BUILDDIR=../../build

# compile 
mkdir -p $BUILDDIR 
sh -c `cd $BUILDDIR && cmake -DCMAKE_BUILD_TYPE=Debug ../ && make`

# run 
$BUILDDIR/$BINDIR/$app # run the program 
echo "run finished"

# generate data
mkdir -p $OUTDIR
gprof -b -A -p -q $BUILDDIR/$BINDIR/$app gmon.out > $OUTDIR/$app-data-$note
echo "output to" $OUTDIR/$app-data-$note
rm gmon.out
