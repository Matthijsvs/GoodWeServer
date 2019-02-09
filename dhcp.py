import socket,struct

# this is a really barebones DHCP implementation in Python.
# currently it supports only 1 client.
# it is designed to return the current PC's IP as gateway AND DNS server.
# this will allow you to create a separate subnet with DNS spoofing.

UDP_IP = "255.255.255.255"
UDP_PORT = 67

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, 25, "eth1"+'\0')
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    stat = ""
    
    msg,typ,add,hop,xid,sec,flg = struct.unpack("!BBBBIHH",data[0:12])
    ptr=12
    for i in range(4):
	#print struct.unpack("!BBBB",data[ptr:ptr+4])
        ptr+=4

    mac=data[ptr:ptr+16]
    stat += mac[0:6].encode('hex')
    ptr+=16+64+128+4; #mac,hostname,filename,cookie

#    print len(data)
#    print ptr
    opt = ord(data[ptr])
    act=0
    while opt<>255:
        l = ord(data[ptr+1])
	#print l
	#print opt
        if opt == 53: #type
           act = ord(data[ptr+2])
	   if data[ptr+2]=="\x01":
                stat += " Discover! "
	   elif data[ptr+2]=="\x03":
                stat += " Request! "
	elif opt==12:
            stat += "Hostname:"
	    stat += data[ptr+2:ptr+l+2]

	ptr+=(l+2)
        opt = ord(data[ptr])
    
    resp = struct.pack("!BBBBIHH",2,1,6,0,xid,0,0x0000)
    resp += struct.pack("!BBBB",0,0,0,0)
    resp += struct.pack("!BBBB",192,168,2,20)
    if act == 1:
        resp += struct.pack("!BBBB",192,168,2,100)
    else:
        resp += struct.pack("!BBBB",0,0,0,0)
    resp += struct.pack("!BBBB",0,0,0,0)
    resp += data[28:240]
    #53 type
    resp += struct.pack("!BB",53,1)
    if act==1:
        resp += struct.pack("!B",2)
    elif act==3:
        resp += struct.pack("!B",5)
    #1 subnet
    resp += struct.pack("!BB",1,4)
    resp += struct.pack("!BBBB",255,255,255,0)
    #3 router
    resp += struct.pack("!BB",3,4)
    resp += struct.pack("!BBBB",192,168,2,100)
    #28 router
    resp += struct.pack("!BB",28,4)
    resp += struct.pack("!BBBB",192,168,2,255)
    #6 DNS
    resp += struct.pack("!BB",6,4)
    resp += struct.pack("!BBBB",192,168,2,100)

    #51 lease time
    resp += struct.pack("!BB",51,4)
    resp += struct.pack("!I",3600)

    #54 dhcp server
    resp += struct.pack("!BB",54,4)
    resp += struct.pack("!BBBB",192,168,2,100)

    #255
    resp += struct.pack("!B",255)
    resp += "\x00"*(300-len(resp))	#padding
    print stat
    sock.sendto(resp,('192.168.2.20', 68))


