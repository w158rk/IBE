from users.Client import Client

client = Client("client")
packet = client.makePacket("EXTR_ASK")

host = "localhost"
port = 12345
client.getPrivateKey()
# client.connectToServer(host, port)
# client.sendPacket(client.socket, packet)
# packet = client.makePacket("IBE_ENC", "wrk", "wrk")
# client.sendPacket("localhost", 12345, packet)
