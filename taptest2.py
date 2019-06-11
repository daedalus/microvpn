from Crypto.Cipher import AES
#from pytun import TapTunnel
from pytun import TunTapDevice,IFF_TAP
import socket
import sys
import lz4.frame

compress = True
debug = False
AESMODE=True

mode = sys.argv[1]
HOST = sys.argv[2]
PORT = int(sys.argv[3])
MTU=9500

if AESMODE:
	PSK = sys.argv[4]
if mode == 'server':
	addr = "10.8.0.1"
else:
	addr = "10.8.0.2"
BLOCK_SIZE=16

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) 
unpad = lambda s : s[0:-ord(s[-1])]

#aes = AES.new(passphrase, AES.MODE_CFB, IV)
aes = AES.new(PSK, AES.MODE_ECB)

def encrypt(raw):
	raw = pad(raw)
        return aes.encrypt(raw)

def decrypt(enc):
        return unpad(aes.decrypt(enc))

def setup_tap(addr,netmask):
	tap = TunTapDevice(flags=IFF_TAP)
        #tap = TapTunnel()
	print tap.name
	tap.addr = addr
	#tun.dstaddr = '10.8.0.2'
	tap.netmask = netmask
	tap.mtu = MTU
	print tap
	#tap.persist(True)
	tap.up()
	return tap

def setup_socket(mode,HOST,PORT):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	if mode == 'server':
		s.bind((HOST,PORT))
		#s.listen(1)
		#s.setblocking(0)
		#conn,addr = s.accept()
                #conn = None
		#while conn == None:
		#	conn, addr = s.accept()
		#return conn
	#else:
	#	s.connect((HOST,PORT))
	#	s.setblocking(0)
	return s


def try_recv(s,size):
	try:
		buf,addr = s.recvfrom(size)
	except:
		buf = ""
		addr = ""
	return buf,addr


def proc1(buf):
	if debug:
        	print ">", buf.encode("hex")
	try:
        	if compress:
        		buf = lz4.frame.compress(buf)
        	if AESMODE:
        		#buf = encrypt(buf,PSK)
                	buf = encrypt(buf)
	except:
		buf = ""
	return buf


def proc2(buf2):
	if debug:
        	print "<",buf2.encode("hex")

	try:
		if AESMODE:
			buf2 =  decrypt(buf2)
		if compress:
			buf2 = lz4.frame.decompress(buf2)
	except:
		buf2 = ""
	return buf2

def main_loop(tap,conn):
	iteration=0
	l2 = 0
	l3 = 0
	if mode != "server":
		addr = (HOST,PORT)
	else:
		addr = None
	while True:

		buf = tap.read(tap.mtu)

		buf = proc1(buf)

		if addr != None:
			try:
				conn.sendto(buf,addr)
			except:
				conn = setup_socket(mode,HOST,PORT)
				conn.sendto(buf,addr)

		buf2,addr = try_recv(conn,tap.mtu)

		if buf2 != "":
			buf2 = proc2(buf2)

		tap.write(buf2)

		l0 = len(buf)
		l1 = len(buf2)
		l2 += l0 
		l3 += l1
		iteration +=1	
		sys.stderr.write("Iter: %d [U: %d kbytes,D: %d kbytes] [total U: %d kbytes,total D: %d kbytes] [total UD: %d kbytes] \r" %  (iteration,l0/1024,l1/1024,l2/1024,l3/1024,(l2+l3)/1024))

tap = setup_tap(addr,"255.255.255.0")
conn = setup_socket(mode,HOST,PORT)
main_loop(tap,conn)

tap.down()
conn.close()
