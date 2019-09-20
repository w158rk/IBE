## 9.20
1. sm4部分的代码添加了可读取文件的操作
2. sm4可生成key，但是传输过程key有无发生改变还未测试
3. 私钥传输的部分在进行调试，调试至`send_enc.c`中

## 9.17
1. 增加了部分注释
2. 将代码中的部分aes_key的部分已经转化为了sm4_key
3. 解决了`handle_ap.c`文件中93行后若干不能继续运行的bug和key错误的bug。

## 问题(2019.9.16)
1. `handle_ap.c`的52行函数的结尾输出的msk和66行开头输出的msk不相符
2. 在运行./servertest和./clienttest进行获取私钥的过程中，`ibe_extract.c`的45行输出的sm9_sk为0
3. 在通信获取私钥的过程中，`ibe_extract.c`的51行会报错，`handle_ap.c`的67行会报错
> 调试过程中对`handle_ap.c`，`ibe_extract.c`和`sys_lib.c`进行了`#define DEBUG`的调试

## 9.15
添加了关于SM4的代码部分，有关的头文件在`include/openssl/sm4.h`下，具体的实现文件在`crypto/sm4.c`中，新增添了`test`中的`sm4test.c`测试用于sm4的测试

## 回答(2019.7.3)

1. 发出部分在`core.c`部分的`run_get_private_key`有用过 

2. 在协议里的头最后有几个0，读0是为了跳过这些0读内容 

另外，关于base和core，因为我现在模块分的还不是非常完善。总的来说，base比较像是功能函数，里面的函数并不能完整的做某一件事情，比如`Read`和`Write`是用来通信收发的，`handle_ibe`和`handle_aes`现在也只是能解密一个包输出信息。而`core`里面的函数是可以实实在在地做一件事情，比如`请求私钥`这样地事情。

## 问题：
1. 只找到了handle_ibe和handle_aes的代码部分，没有找到ibe和aes加密发出的部分
2. 注释为读0那块代码的作用
    
