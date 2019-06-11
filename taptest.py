#from pytun import TapTunnel
from pytun import TunTapDevice,IFF_TAP
import socket
import sys

debug = False
AESMODE=False

mode = sys.argv[1]
HOST = sys.argv[2]
PORT = int(sys.argv[3])
if AESMODE:
	PSK = sys.argv[4]

if mode == 'server':
	addr = "10.8.0.1"
else:
	addr = "10.8.0.2"

BLOCK_SIZE=16

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) 
unpad = lambda s : s[0:-ord(s[-1])]

 # AES encryption: (plaintext -> decrypted)
def encrypt(message, passphrase):
    # passphrase MUST be 16, 24 or 32 bytes long, how can I do that ?
    #IV = Random.new().read(BLOCK_SIZE)
    aes = AES.new(passphrase, AES.MODE_CFB, IV)
    return base64.b64encode(IV) + " " +  base64.b64encode(aes.encrypt(message))

 # AES decryption (crypted -> plaintext)
def decrypt(encrypted, passphrase, IV = None):
    if IV == None:
        IV = Random.new().read(BLOCK_SIZE)
    else:
        IV = base64.b64decode(IV)
    aes = AES.new(passphrase, AES.MODE_CFB, IV)
    return aes.decrypt(base64.b64decode(encrypted))

def setup_tap(addr,netmask):
	tap = TunTapDevice(flags=IFF_TAP)
        #tap = TapTunnel()
	print tap.name
	tap.addr = addr
	#tun.dstaddr = '10.8.0.2'
	tap.netmask = netmask
	tap.mtu = 1500
	print tap
	#tap.persist(True)
	tap.up()
	return tap

def setup_socket(mode,HOST,PORT):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	if mode == 'server':
		s.bind((HOST,PORT))
		s.listen(1)
		#s.setblocking(0)
		#conn,addr = s.accept()
                conn = None
		while conn == None:
			conn, addr = s.accept()
		return conn
	else:
		s.connect((HOST,PORT))
		s.setblocking(0)
	return s


def try_recv(s,size):
	try:
		buf = s.recv(size)
	except:
		buf = ""
	return buf

def main_loop(tap,conn):
	iteration=0
	l2 = 0
	l3 = 0
	while True:
		buf = tap.read(tap.mtu)
	        if debug:
        	    print ">", buf.encode("hex")
		if AESMODE:
			buf = encrypt(buf,PSK)

		try:
			conn.send(buf)
		except:
			conn = setup_socket(mode,HOST,PORT)
			conn.send(buf)

		buf2 = try_recv(conn,tap.mtu)
	        if debug:
        	    print "<",buf2.encode("hex")
		if buf2 != "":
			if AESMODE:
				buf2 =  decrypt(buf2,PSK)
			tap.write(buf2)
		l0 = len(buf)
		l1 = len(buf2)
		l2 += l0 
		l3 += l1
		iteration +=1	
		sys.stderr.write("iter: %d [> %d bytes,< %d bytes] [> %d bytes,< %d bytes] [total: %d kbytes] \r" %  (iteration,l0,l1,l2,l3,(l2+l3)/1024))

tap = setup_tap(addr,"255.255.255.0")
conn = setup_socket(mode,HOST,PORT)
main_loop(tap,conn)

tap.down()
conn.close()
