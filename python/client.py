from users.Base import Client

client = Client("client")
packet = client.makePacket("IBE_ENC", "wrk", "wrk")
client.sendPacket("localhost", 12345, packet)
packet = client.makePacket("EXTR_ASK")
client.sendPacket("localhost", 12345, packet)
