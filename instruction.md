## 顶级节点ss
1. 生成顶级域的mpk文件`mpk-global.conf`
2. 生成自己在顶级域中的私钥文件`sk-global_id.conf`

---
## 顶级节点生成自己的节点域
1. 运行`Set up your system`生成节点域的mpk文件`mpk-id.conf`，节点域的msk文件`msk.conf`以及私钥文件`sk_id.conf`
    > 其中另外还保存了mpk长度文件`mpk-len.conf`，msk长度文件`msk-len.conf`，私钥长度文件`sk-len_id.conf`
2. 运行`Read your system files`读取自己的参数并生成自己的证书文件`sign_id.conf`和证书长度文件`sign-len_id.conf`

---
## 非顶级节点生成自己的节点域
1. 运行`Set up your system`生成节点域的mpk文件`mpk-id.conf`，节点域的msk文件`msk.conf`以及私钥文件`sk_id.conf`
    > 其中另外还保存了mpk长度文件`mpk-len.conf`，msk长度文件`msk-len.conf`，私钥长度文件`sk-len_id.conf`
2. 运行`Read your system files`读取自己的参数**不生成新的证书文件**


---
## 节点获取父节点及顶级域的mpk
1. 父节点默认先运行`Read your system files`读取自己的参数
2. 子节点运行`Get global and domain mpk`获取父节点的mpk文件`mpk-fatherid.conf`，顶级域的mpk文件`mpk-global.conf`以及mpk的长度文件`mpk-len.conf`

---
## 节点加入节点域
1. 节点在加入域之前需要先运行`Get global and domain mpk`获取相关文件
2. 父节点默认先运行`Read your system files`读取自己的参数
3. 子节点运行`Extract your Private Key`获取自己在父节点域中的私钥文件`sk-domain_id.conf`，证书文件`sign_id.conf`以及证书的长度文件`sign-len_id.conf`

---
## 域内节点进行通信
1. 节点运行`Send message`进行信息的传输，非顶级结点解密时用的是自己的`sk-domain_id.conf`文件中的私钥，顶级结点用的是`sk_id.conf`文件中的私钥。

---
## 域间节点通信前身份验证
1. 节点A运行`Try to send message cross-domain`，节点A将自己父节点域的mpk和证书发送给节点B。
   
   ***注意：*** 当节点A为顶级节点的时候，发送的是自己生成域的mpk。
2. 节点B对节点A的证书进行验证，验证成功后，将自己父节点的mpk和证书发送给节点A，节点B得到节点A的mpk文件`mpk-A.conf`。
   
   ***注意：*** 当节点B为顶级节点的时候，发送的是自己生成域的mpk。
3. 节点A对节点B的证书进行验证，得到节点B的mpk文件`mpk-B.conf`。
4. 之后可以运行`Send message`进行信息的传输

---
## 注意：
1. 顶级节点拥有2个mpk文件和2个sk文件，顶级域的为`mpk-global.conf`和`sk-global_id.conf`，自己生成的域的为`mpk-id.conf`和`sk_id.conf`。在进行通信加解密及跨域身份验证的时候使用的是`mpk-id.conf`和`sk_id.conf`。
2. 除顶级节点外的管理节点也拥有2个mpk文件和2个sk文件，父节点域的为`mpk-fatherid.conf`和`sk-domain_id.conf`，自己生成的域为`mpk-id.conf`和`sk_id.conf`。在进行通信加解密及跨域身份验证的时候用的是`mpk-fatherid.conf`和`sk-domain_id.conf`。在子节点申请获取sk的时候用的是`mpk-id.conf`和`sk_id.conf`。
3. 除了顶级节点证书是到自己生成域的其他节点证书均到自己父节点的域，因此，顶级节点通信过程中解密用的是非domain的sk参数。

---
## 证书的结构说明
### 顶级节点
顶级结点通过运行`Read your system files`生成自己的证书
```
{
    ID = server.ID;
    PP = mpk-ID.conf;
    sign = ENCsk-global(ID||PP)
    next* = {
        ID = server.ID;
        PP = mpk-global.conf;
        sign = NULL;
        next* = nullptr;
    }
}
```
### 非顶级节点
非顶级节点通过运行`Extract your Private Key`在获取自己私钥的同时，获取父节点给自己生成的证书
```
{
    ID = user.ID;
    PP = mpk-fatherID.conf;
    sign = ENCsk-fatherID(ID||PP)
    next* = fathernode.SignMesg;
}
```