# 协议设计 

整体协议分两层，加密头定义的协议和应用层消息 

## 加密消息协议 

### IBE 

|      | type  | 消息长度 | 空 |
| ---  | ---   |  ---| ---|
|长度   | 1    | 4|                 19|
|值     | 0    | 整个包（含头）的长度|0|

### AES

|       | type  |      iv	    |  消息长度 | 空 |
| ---  | ---   |   ----     | ---|       ---|
|长度   | 1     |     16	    |  4|       3|
|值     | 1  |   初始向量 | 整个包的长度| 0|

## protocol of the application layer 

<!-- ### apply for the private key 

|     | type | ID length | ID | null | 
| --- | --- | --- | --- | --- |
| length (bytes) |  4                    | the number which the ID length represents | 
| value          |  the length of the id |   -->