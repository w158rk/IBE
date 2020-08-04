# 跨域通信

`Client3`和`Client1`

- client3:
```
python3 python/server.py -c ./client.json
```

- client1:
```
python3 python/client.py -c ./client.json --action comm --addr localhost --port 5007 --id Client3 --key IOT
```

- 验证
```
diff IOT-Client3.conf ../client3/IOT-Client1.conf
```

# 与父节点通信 

`Client4`和`Client1` 

- client1:
```
python3 python/server.py -c ./client.json
```

- client4:
```
python3 python/client.py -c ./client.json --action comm-no-auth --addr localhost --port 5004 --id Client1 --key IOT
```

- 验证 
```
diff IOT-Client1.conf ../client1/IOT-Client4.conf
```

# 与同域兄弟节点通信

`Client2`和`Client1` 

- client1:
```
python3 python/server.py -c ./client.json
```

- client2:
```
python3 python/client.py -c ./client.json --action comm-no-auth --addr localhost --port 5004 --id Client1 --key IOT
```

- 验证 
```
diff IOT-Client1.conf ../client1/IOT-Client2.conf
```
