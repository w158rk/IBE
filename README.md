# C语言部分

## Windows 平台

### dependency

cmake、MinGW-gcc、MinGW-g++、MinGW-make、MinGW-libgmp

> 都是极其好安装配置的工具呀！ 

### 编译执行

在项目目录下执行命令 

```
make
```

即可得到可执行文件，位于目录`build\bin`下。

* `$ .\build\bin\init.exe`  --- 建立系统
* `$ .\build\bin\extract.exe [username]`  --- 得到公钥私钥
* `$ .\build\bin\encrypt.exe [username] [message]`  --- 得到密文
* `$ .\build\bin\decrypt.exe [username]`  --- 解密密文

## Linux 平台

### dependency 

cmake、gcc、g++、Makefile、libgmp

> 都是 sudo apt install 可以解决的

### 编译执行

执行如下命令

```
make
```

* `$ .\build\bin\init`  --- 建立系统
* `$ .\build\bin\extract [username]`  --- 得到公钥私钥
* `$ .\build\bin\encrypt [username] [message]`  --- 得到密文
* `$ .\build\bin\decrypt [username]`  --- 解密密文

# Python语言部分

## 当前功能 

client用server的公钥加密一段消息发送给server，server用自己的私钥解密

## 带实现


