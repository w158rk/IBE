# Private Key Request 

This example is written for showing the procedure of requesting for a user's private key.
The three users are:

```
Server1:    one of the top user
Server2:    the other one of the top user 
Client:     one of the users under the administration of Server1
```

First of all, the two top servers should initialize the system. For that purpose, the `Server1` first open a server process(`server.py), then the `Server2` trigger an initialization using `client.py`. The process is finished when you see the message: "The initialization has finished" in both the consoles.

Now you can see the global cryptographic parameters in both the two directory, with name `mpk-global.conf` and `sk-global.conf`. The other files are auxiliary and **should be removed later**.

Now you have the two server setup, then reopen the two servers for the following functionality. We take `Server1` as an example. It should make a local domain for manage its child nodes. Assume `Client` is one of children of `Server1`. `Client` must define this parent-child relationship in its configuration.