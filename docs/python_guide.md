## 运行指南

1. 配置C库位置
```python
# constant.py
ROOT_DIR = "/home/{path-to-find-IBE}/IBE"

2. 配置用户json文件，例如[init_server.json](../example/init/server1/init_server.json)

其中，能作为父节点的json文件需要有'admin_mpk_file'，'admin_msk_file'，'admin_sk_file'

顶级节点的json文件需要有'global_sk_file'

3. 如果要运行顶级功能，配置顶级用户目录，如[top_user_list.json](../example/init/top_user_list.json)并在用户配置文件中加入 

```json 
"top_user_list": "../top_user_list.json"
```

现有'example'为测试文件夹，‘init’用于顶级参数生成的测试，'sk'用于私钥申请的测试，'comm'用于会话密钥申请的测试

其中'comm'文件夹下各节点的关系为：

     Server1         Server2
    
    /       \           |

Client1  Client2     Client3

   |
Client4

   |

Client5

   |

Client6

   |

Client7

   |

Client8

4. 链接python目录
```sh
ln -s {path-to-IBE}/src/python .
```

5. 运行server。运行server不需要指定功能，直接 
```sh 
python3 python/server.py -c {config-file}
```

6. 运行client，需要指定运行的功能
```sh 
python3 client.py -h
usage: client.py [-h] [--server-ip SRV_ADDR] [--server-port SRV_PORT]
                 [--action {init,sk,comm}] [-c [CONFIG_FILE]] 
                 [--addr comm_addr] [--port comm_port] [--id comm_id]
                 [--key {sm4,IOT}]
```

## 代码架构

现阶段代码测试的数据如下：

- 第二层节点sk请求 发送数据最大量5006
- 第三层节点sk请求 发送数据最大量8398
- 第四层节点sk请求 发送数据最大量12902
- 第五层节点sk请求 发送数据最大量18894
- 第六层节点sk请求 发送数据最大量18894
- 第七层节点sk请求 发送数据最大量32768

- 第二层节点密钥协商 发送数据最大量3574 验证时间92.76ms
- 第三层节点密钥协商 发送数据最大量6110 验证时间145.40ms
- 第四层节点密钥协商 发送数据最大量9486 验证时间186.30ms
- 第五层节点密钥协商 发送数据最大量13986 验证时间234.78ms
- 第六层节点密钥协商 发送数据最大量19990 验证时间319.94ms

因此目前通信data开辟的最大数据量个数为40000，具体定义在[constant.py](../src/python/constant.py)中的`RECEIVE_BUFFER_SIZE`里

### 证书的结构

```python
class Certificate:
    _valid_attrs = [
        "header",
        "payload",
        "sig"
    ]

class Header:
    _valid_attrs = [
        "type",
        "alg"
    ]

class Payload:
    _valid_attrs = [
        "iss",
        "aud",
        "exp",
        "nbf",
        "iat",
        "mpk",
        "parent"
    ]

class Signature:
    _valid_attrs = [
        "header",
        "payload",
        "sig"
    ]

```

其中，`iss`为证书的发布用户，'aud'为证书的授权用户，'mpk'为该用户的local mpk，'parent'为该用户父节点的证书，'sig'为用于验证证书的签名


### IOT会话密钥的结构

```python
class IOT_key:

    _valid_attrs = [
        "time_stamp",
        "end_time",
        "key"
    ]
```

其中，`time_stamp`为该key开始生效的时间戳，`end_time`为生效到期的时间戳，`key`为协商出的sm4会话密钥