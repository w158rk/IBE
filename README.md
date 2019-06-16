# 编译

```
mkdir build
cd build
cmake ../
make
```

# 运行 

```
./sm9test               // 生成配置文件 
./servertest            // 运行server
./client                // 运行client
```

运行结果：Server 获取到 Client 的ID 和 AES 密钥

```
decrypted text : Client
decrypted text length : 52
```

# todo 

* 协议完善 
    1. <del>IBE通信</del>
    1. 服务器收到用户ID 和 AES 密钥后，生成相应的私钥，用AES加密
        （IV由服务器选择，将IV和加密后的私钥按照协议格式发送给客户端）
    2. 客户端收到AES加密的密钥，解密后获取私钥保存到本地 
    3. 某一实体向另一实体发起密钥协商请求，请求附带内容为本方的$MPK_A$ 
    4. 实体收到密钥协商请求后返回密钥协商ACK，附带内容为本方的$MPK_B$和$Enc_{MPK_A, ID_A}(key_B)$
    5. 实体收到协商ACK后返回ACK_2，附带内容为$Enc_{MPK_B, ID_B}(key_A)$
    （要不要再加一轮ACK待后续修改）
    6. 会话密钥协商结束后用$(key_A||key_B)$为AES密钥的通信设计
* 秘密共享 
* 签名和认证
