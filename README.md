# 编译

```
mkdir build
cd build
cmake ../
make
```

# Documents 

```
doxygen Doxyfile
firefox docs/html/index.html &
```

# run tests

## get the configure files

```
./sm9test               // 生成配置文件 
```

## run the simple communication 

```
./servertest            // 运行server
./client                // 运行client
```

运行结果：Server 获取到 Client 的ID 和 AES 密钥
```
decrypted text : Client
decrypted text length : 52
```

## test the secret sharing functions 

```
./sstest                // test the secret sharing functions
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
    1. <del>generate a random polynomial</del>
    2. <del>get the value of f(x) given the x</del>
    3. <del>get the value of the lagrange polynomial $l_i(x)$ given the x</del>
    4. <del>point addition</del>
    5. <del>scalar multiplication</del>
* 签名和认证

# notes 

## functions for point addition and scalar multiplication 

```c
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 const EC_POINT *b, BN_CTX *ctx);

int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                  size_t num, const EC_POINT *p[], const BIGNUM *m[],
                  BN_CTX *ctx);
```
