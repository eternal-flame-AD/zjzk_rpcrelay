import socket
import socketserver
import threading
import queue
import binascii
from pyDes import des, CBC, PAD_PKCS5
import serverconfig
import time
import rpcparse
def des_encrypt(s):
    """
    DES 加密
    :param s: 原始字符串
    :return: 加密后字符串，6进制
    """
    secret_key = serverconfig.rpckey.encode('utf-8')
    iv = serverconfig.rpciv
    k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    en = k.encrypt(s, padmode=PAD_PKCS5)
    return binascii.b2a_hex(en)

def des_decrypt(s):
    """
    DES 解密
    :param s: 加密后的字符串，16进制
    :return:  解密后的字符串
    """
    secret_key = serverconfig.rpckey.encode('utf-8')
    iv = serverconfig.rpciv
    k = des(secret_key, CBC,iv, pad=None, padmode=PAD_PKCS5)
    de = k.decrypt(binascii.a2b_hex(s), padmode=PAD_PKCS5)
    return de

def decrypt_packet(s):
    data=binascii.hexlify(s)
    try:
        payload=des_decrypt(data[8:])
        return 'size='+str(rpcparse.getint(data[0:8]))+'data='+str(payload)
    except:
        pass
    return "Failed to Decrypt...Raw data:"+str(s[8:])

class upstream_server():
    def __init__(self):
        self.conn=socket.create_connection((serverconfig.upserver_ip,serverconfig.upserver_port))
        print("server connected")
    def sender(self):
        global upacket_queue
        while True:
            pkt=upacket_queue.get()
            #print('sending pkt to server')
            self.conn.send(pkt)
    def recver(self):
        global dpacket_queue
        while True:
            pkt=self.conn.recv(serverconfig.maxsize)
            print("RX:",decrypt_packet(pkt))
            dpacket_queue.put(pkt)
      
class downstream_server():
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    global upacket_queue,dpacket_queue
    '''
    def pusher(self): #推送数据
        global dpacket_queue
        while True:
            pkt=dpacket_queue.get()
            self.request.sendall(pkt)
    ''' 
    def __init__(self):
        self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((serverconfig.dnserver_ip, serverconfig.dnserver_port))
        self.s.listen(1)
        self.conn, self.remoteaddr = self.s.accept()
    def sender(self):
        global dpacket_queue
        while True:
            pkt=dpacket_queue.get()
            #print('sending pkt to client')
            self.conn.send(pkt)
    def recver(self):
        global upacket_queue
        while True:
            pkt=self.conn.recv(serverconfig.maxsize)
            print("TX:",decrypt_packet(pkt))
            upacket_queue.put(pkt)

def upstream_server_thread():
    global upacket_queue,dpacket_queue
    print("starting upstream")
    serv=upstream_server()
    sender=threading.Thread(target=serv.sender,name="upsender")
    recver=threading.Thread(target=serv.recver,name="uprecver")
    sender.daemon=True
    recver.daemon=True
    sender.start()
    recver.start()
    print("upstream started")

def downstream_server_thread():
    global upacket_queue,dpacket_queue
    # Create the server, binding to localhost on port 9999
    print("starting dnstream")
    serv=downstream_server()
    sender=threading.Thread(target=serv.sender,name="dnsender")
    recver=threading.Thread(target=serv.recver,name="dnrecver")
    sender.daemon=True
    recver.daemon=True
    sender.start()
    recver.start()
    print("dnstream started")

def main():
    global upacket_queue,dpacket_queue
    upacket_queue=queue.Queue(100)
    dpacket_queue=queue.Queue(100)
    ups=threading.Thread(target=upstream_server_thread,name="upstream")
    dns=threading.Thread(target=downstream_server_thread,name="dnstream")
    ups.daemon=True
    dns.daemon=True
    ups.start()
    dns.start()
    while threading.active_count() > 0:
        time.sleep(0.1)
main()