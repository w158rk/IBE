from user import Client

client = Client("client")
client.send("wrk", "wrk", "localhost", 12345)