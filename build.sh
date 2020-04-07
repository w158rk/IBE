#/bin/bash

mkdir -p .gmssl 
cd .gmssl 
if [ -d ".git" ]; then
    git pull origin master 
else 
    git clone https://github.com/w158rk/GmSSL.git ./ 
fi
echo "clone the repository finished ... "

mkdir -p build 
cd build 
../config --debug 
make 
export IBE_LIB=`pwd`

echo "make the library finished ..."

cd ../../
mkdir -p build
cd build 
cmake -DCMAKE_BUILD_TYPE=Debug ../
make
