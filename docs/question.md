## 1.7
**问题：**
1. 运行init-client和init-server会有段错误
2. init后生成的sP文件的名称应该为`mpk-global.conf`，加id名字的是后来自己生成的域的
3. 在usertest.cpp中添加了一行[link](../src/test/usertest.cpp#43)只是为了能顺利跑通，但是不知道你加mode的本意是啥，后期若有需要可以再改掉，并加了clienttest用于区分client和server
4. [link](../src/user/server.cpp#157)改回去了，将mode分开，顶级的采用init，下层的包括顶级结点生成自己的域都不用init的mode

**添加：**
1. 添加了app中的CMakeLists文件生成init-client和init-server的可执行文件，去掉了gitignore中的.txt
2. 加入了server.json和client.json配置文件

**解决的bug：**
1. 在client申请获取server的sP是得到的文件名应为server的id而不是client的id
2. 在verify的时候id固定为了client，会导致server发给client的验证不通过
3. 将申请获取mpk后得到的mpk文件的名字改为了`mpklen.conf`

## 12.1

- 顶级域的mpk文件`mpk-global.conf`
- 父节点给的用于通信的mpk文件`mpk-Server.conf`
- 节点自己产生的域的mpk文件`mpk-Client.conf`

## 11.26
1. 添加了`GET_AND_SET(SignMesg *, signature)`的功能

## 11.25

需要解决的问题：
1. 每个user获取到的sign需要进行保存，保存前默认为NULL
2. 在发送sign前需要计算一个长度（可以存放签名的长度）
3. 需要获取顶级的sP过程

## 11.24
1. 在ds.hpp中添加了SignMesg的结构体
2. 加入了sign的获取函数`get_signdata`，但是其中mpk的值的获取部分还没改
3. 加入了`SIGN_REQUEST_TYPE`，注释掉了`SESSION_KEY_FINAL_TYPE`
4. `clientjson`中加入了`msk_file`和`msk_len_file`

## 11.5
1. 解决IBE加解密的问题
2. 段错误的问题在于type的值在packet_send的过程中出现了改变
3. enc中最后直接从app_packet中能读出type，从sec中的app_packet不行

## 10.30
1. `crypto.h`中sm4 key生成的函数改为`gen_random_sm4`
2. sm4的长度问题解决

## 10.29

把crypto里的set_sm4key改成gen或random开头的函数 

## 10.28
问题：server在生成私钥并进行sm4加密后，`packet_send.cpp`的第78行文件写不进去，主要问题出现在`connection.c`的第112行wirte函数中

解决方法：将HEAD和payload.data中的内容连起来然后一并写入
1. client连上server后继续监听
2. `handle_sk_response`完成

**问题：**
1. `handle_dk_response`中对sk进行验证莫名的问题，后期再完善
2. IBE解密server用的是client的私钥？？？client找不到私钥
3. sm4_key还是有概率出错啊，会报`some members not set`的错

**待解决：** sm4加密后的长度

## 10.27
1. 修改set_key()的问题解决

## 10.26

**TODO** : 给sm4加密的mode定义宏 [link](src/packet/send_enc.cpp#L108)

**TODO** : 重写handle_sk_response [link](src/packet/handle_ap.cpp#L161)

**TODO** : 计算sm4加密的长度 [link](src/packet/send_enc.cpp#L120)

**TODO** : 存取长度的位置用网络序 (`K`)

**TODO** : 修改set_key(): 1. 不能用文件; 2. 要写sm4  [定义](./src/crypto/sm4.c#L347), [调用](./src/user/core.cpp#L91)

**TODO** : IBE_MS_LEN 可能是140。。 会导致extract失败

1. 加入PacketException 
2. 删除SecPacket payload域的sk_data 
3. 在ID中保留ip和port 
4. 加入json配置文件 

**Q**: 连上服务器要不要监听？

[答10.22问题](#10.22)：可能压根不是一个ctx，已经把sm4存在Packet对象里了

## 10.22
问题：`packet.hpp`中的sm4key有的时候会莫名被清零。

## 10.21
1. 为了在内存中存储sm4key，在`packet.hpp`中类的public添加了`unsigned char sm4key[16];`。然后在`send_ap.cpp`判断是否是获取私钥，如果是保存`ctx->payload.appPacket->packet`中前16位的sm4key，再`handle_dec.cp`中使用
2. 后期在处理`sm4.h`的时候要把现在一些16数据的地方改为`SM4_KEY_LEN`
3. 功能可以运行
4. sm4头文件更改完成，2步骤完成
5. 宏文件名已添加

## 10.20
记录改动的地方：
1. `utils.h`中定义的文件名字应为`client_id->id`
2. `send_enc`中在生成data的时候应为
```c
memcpy(data, app_packet->head, APP_HEAD_LEN);
memcpy(data+ APP_HEAD_LEN, app_packet->payload, length); 
```
3. 解密部分的代码
```c
char *m = (char *)malloc(BUFFER_SIZE);
IBEPrivateKey sk = NULL;
size_t m_len;
get_sk_fp("sk_Server.conf", &sk);
ibe_decrypt(p_sec_packet->payload.data, c_len, m, &m_len, &sk);
fprintf(stderr, "m is %s\n", m);
```

## 10.16
1. sm9私钥长度虽然偶尔不是313，但是可以正常加解密！！！
2. 解决了IBE加解密通信的bug，现在可以server和client之间进行互通消息了
3. 问题1：sm4加密的时候HEAD没有加进去，加进去私钥部分的会发生改变
4. sk的文件必须要用`get_sk_fp(filename, &sk);`读取，定义方式为`IBEPrivateKey sk`
5. 问题2：通信结束虽然能生成文件，但是不能正常结束
6. 添加了sk获取时与父节点通信的过程

## 10.14
1. sm4的问题解决，可以对私钥进行正常的加解密
2. sm9生成秘钥的过程中存在偶尔长度不为313的问题
3. 加解密通信在调

## 10.12
1. 密钥直接生成并进行加解密时不会出现错误

## 10.7
1. `sm4`在进行加密的时候容易在换行等位置停止
   
## 9.25
1. 完成了通信的加解密部分，需要加密的文件用id_message.txt保存，解密得到的会输入到dec_message.txt中

## 9.23
1. 私钥获取部分完成，获取后会生成sk_的文件
2. 私钥从文件中读取的方式正在探索，需要处理换行的问题

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
> 调试过程中对`handle_ap.c`，`ibe_extract.c`和`sys_lib.c`进行了``的调试

## 9.15
添加了关于SM4的代码部分，有关的头文件在`include/openssl/sm4.h`下，具体的实现文件在`crypto/sm4.c`中，新增添了`test`中的`sm4test.c`测试用于sm4的测试

## 回答(2019.7.3)

1. 发出部分在`core.c`部分的`run_get_private_key`有用过 

2. 在协议里的头最后有几个0，读0是为了跳过这些0读内容 

另外，关于base和core，因为我现在模块分的还不是非常完善。总的来说，base比较像是功能函数，里面的函数并不能完整的做某一件事情，比如`Read`和`Write`是用来通信收发的，`handle_ibe`和`handle_aes`现在也只是能解密一个包输出信息。而`core`里面的函数是可以实实在在地做一件事情，比如`请求私钥`这样地事情。

## 问题：
1. 只找到了handle_ibe和handle_aes的代码部分，没有找到ibe和aes加密发出的部分
2. 注释为读0那块代码的作用
    
