#!/usr/bin/python
# Author: Branislav Brujic - Bug
# Email: branislav.brujic@gmail.com

from socket import *
from select import select
import random, sys, time, memcache, threading
myHost = ''
myPort = 50006
mainsocks, readsocks, writesocks = [], [], []

## FUNCTIONS ##
def get_ip_info(s, ip):
    res = s.get(ip)
    #return 
    if res == None:
      return 0;
    elif res == 'ok':
      return 1
    else:
      print str(res);
      return 0

def handle_client(mem_conn, ip, sock_conn):
  result = get_ip_info(mem_conn, ip)
  if(int(result) != 1):
    print str(result)+' '+str(ip)
  sock_conn.sendall(str(result)) 
        
## START SERVER ##
portsock = socket(AF_INET, SOCK_STREAM)
portsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
try:
  portsock.bind((myHost, myPort))
  portsock.listen(10000) # max connections at time, 5 is default
  portsock.setblocking(0) # non blocking connection
  portsock.settimeout(5)
except Exception:
  print "Port: "+str(myPort)+" in use by other application. Runing Failed!"
  sys.exit()

#background application - daemon

#start memcached connection
mem_conn = memcache.Client(["192.168.1.211:11211"]) # memcache conection

mainsocks.append(portsock)
readsocks.append(portsock)

try:
  while True:
    readables, writeables, exeptions = select(readsocks, writesocks, [])
    for sockobj in readables:
      if sockobj in mainsocks:
	newsock, address = sockobj.accept()
	readsocks.append(newsock)
      else:
	data = sockobj.recv(16)
	if not data:
	  sockobj.close()
	  readsocks.remove(sockobj)
	else:
	  t = threading.Thread(target=handle_client, args=(mem_conn, data, sockobj))
	  t.daemon = True
	  t.start()
except KeyboardInterrupt:
  # quit
  print "\nProgram closed"
  sockobj.close()
  sys.exit()
  
  
  
  
  