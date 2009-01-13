#!/usr/bin/python

import socket
from urlparse import urlparse

hosts = []

file = open ('../hosts-w3-msql.txt')
while 1:
    line = file.readline ()
    if not line:
        break
    
    o = urlparse(line) 

    if o.hostname:
        if hosts.count (o.hostname) == 0: 
            hosts.append (o.hostname)

file.close ()

print hosts

for host in hosts:
    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
    
    s.settimeout (10)

    print "Trying " + host

    try:
        s.connect ((host, 1114))
    except socket.error, msg:
        print "Connection failed with " + host
        s.close ()
        s = None
        continue
    
    s.setblocking (1)

    print "Success with " + host
 
    while 1:
        line = s.recv (256)
        if not line:
            break;
        print line

    s.close ()
