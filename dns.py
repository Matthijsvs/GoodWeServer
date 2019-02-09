import socket,struct

# this is a barebones DNS server in python.
# it will always return a single IP for every hostname, usefull when redirecting web traffic.

UDP_IP = "192.168.2.100"
UDP_PORT = 53

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
	peer, addr = sock.recvfrom(1024) # buffer size is 1024 bytes

	############# request handling ############
	xid,flags,questions,ansRR,authRR,addRR = struct.unpack("!HHHHHH",peer[0:12])
	start = 12
	if (flags and 0x8000>0): #request bit is set
		for i in range(questions):
			n = ""
			while ord(peer[start])>0:
				l= ord(peer[start])
				n+=peer[start+1:start+1+l]
				start=start+l+1
				if ord(peer[start]) >0:
					n+="."
			print "Request name:{0:s}".format(n)

			typ,cls=struct.unpack("!HH",peer[start+1:start+5])
			q=peer[12:start+5]

	############ response handling ###############
	#set flags
	flags =0x8180
	ansRR=1
	addRR=0

	resp = struct.pack("!HHHHHH",xid,flags,questions,ansRR,authRR,addRR);
	resp +=q
	nm = 49164 #pointer 
	ttl=3600
	length=4
	l = socket.inet_aton(UDP_IP)
	add = struct.unpack('!BBBB',l)
	resp += struct.pack("!HHHIHBBBB",nm,typ,cls,ttl,length,add[0],add[1],add[2],add[3])
	sock.sendto(resp,addr)
