#!/usr/bin/env python
# encoding: utf-8

from routetable import RtTable
import struct
import eventlet
from eventlet.green import socket
import time


"""
struct
https://docs.python.org/2/library/struct.html
https://www.cnblogs.com/gala/archive/2011/09/22/2184801.html
iproute
http://docs.pyroute2.org/ipdb.html#ipdb-vs-iproute
"""

MAXM = 16

def period_task(period=5):
    def decorator(func):
        def _do_task(*args, **kw):
            while True:
                eventlet.sleep(period)
                func(*args, **kw)
        def _period_task(*args, **kw):
            eventlet.spawn_n(_do_task, *args, **kw)
        return _period_task
    return decorator

def iptostr(ip):
    ips = ip.split('.')
    res = ''
    for i in range(4):
        s = bin(int(ips[i]))[2:]
        while True:
            if len(s) ==8:
                break
            s = '0'+s
        res = res + s
    return res

class RouteInformantionProtocol():
    def make_response(self, routes):
        """here rip v1 doesn't support subnet mask,it's receiver's responsibility
        to determin subnet"""
        head = struct.pack('!bbhhh', 2, 1, 0, 2, 0)
        print(routes)
        msg = head
        for r in routes:
            ips=r['ip'].split('/')[0].split('.')
            msg = msg + struct.pack('!BBBBiii', int(ips[0]), int(ips[1]), int(ips[2]), int(ips[3]), 0, 0, r['metric'])
        return msg

    def parser_packet_tail(self, tail):
        routes = []
        while True:
            ips1,ips2,ips3,ips4, _, _, metric = struct.unpack("!BBBBiii", tail[:16])
            ipaddr=str(ips1)+"."+str(ips2)+"."+str(ips3)+"."+str(ips4)
            maskstr = iptostr(ipaddr)
            mask = 32
            while True:
                if maskstr[(mask-1):] == '1':
                    break
                mask = mask -1
                maskstr = maskstr[:mask]

            ipaddr=ipaddr+'/'+str(mask)
            routes.append({'ip':ipaddr, 'metric':metric})
            tail = tail[16:]
            if tail == "":
                break
        return routes

    def parser_packet_head(self, head):
        cmd, version, _, addrf, _ = struct.unpack("!bbhhh", head)
        if cmd == 1:
            return "REQUEST"
        elif cmd == 2:
            return "RESPONSE"



class RipServer(RouteInformantionProtocol):
    def __init__(self):
        self.rttable = RtTable()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.sock.bind(('0.0.0.0', 520))
        self.check_route_table()
        self.period_sendresponse()

    @period_task(period=5)
    def period_sendresponse(self):
        for dr in self.rttable.direct_table:
            sourceip = dr['prefsrc']
            port = dr['oif']
            self.pre_response(sourceip, port, horizonsplit=False)

    @period_task(period=1)
    def check_route_table(self):
        routes = self.rttable.get_all_route()
        now = time.time()
        for r in routes:
            if now - r['timer'] > 120 and r['metric'] == MAXM:
                self.rttable.remove_route(r)
                self.rttable.remove_rip_route(r)
            if now - r['timer'] > 180:
                self.routetimeout(r)

    def routetimeout(self, route):
        route['metric'] = MAXM
        self.rttable.update_route(route)


    def trigledupdate(self, route):
        pass


    def get_localip_by_source(self, source):
        direct_table = self.rttable.direct_table
        for r in direct_table:
            mask = int(r['dst'].split('/')[1])
            binarystr1 = iptostr(r['dst'].split('/')[0])
            binarystr2 = iptostr(source[0])
            #here just get the firsh match cidr, strictly, need to match the longest one
            if binarystr1[:mask] == binarystr2[:mask]:
                return (r['prefsrc'],r['oif'])

    def request(self, source):
        sourceip, sourceport = self.get_localip_by_source(source)
        self.pre_response(sourceip, sourceport)

    def pre_response(self, sourceip, sourceport, horizonsplit=True):
        rers = []
        routes = self.rttable.get_all_route()
        for r in routes:
            if r['interface'] == sourceport:
                continue
            if r['metric'] == MAXM:
                continue
            rers.append({'ip': r['dst'], 'metric': r['metric']})
        for r in self.rttable.direct_table:
            if r['oif'] == sourceport and horizonsplit == True:
                continue
            rers.append({'ip': r['dst'], 'metric': 1})

        msg = self.make_response(rers)
        self.do_response(sourceip, msg)

    def response(self, recvData, source):
        newroutes = self.parser_packet_tail(recvData)
        riproutes = self.rttable.get_all_route()
        directroute= self.rttable.direct_table
        localip, port = self.get_localip_by_source(source)
        for nr in newroutes:
            flag=1
            for dr in directroute:
                if dr['dst'] == nr['ip']:
                    flag=0
                    break
            if flag == 1:
                if nr['metric'] == MAXM:
                    continue
                for rr in riproutes:
                    if rr['dst'] == nr['ip']:
                        flag=0
                        if rr['metric'] > nr['metric'] + 1:
                            route={"dst": rr['dst'],
                                   "metric": nr['metric'] + 1,
                                   "gateway": source[0],
                                   "interface": port,
                                   "timer": time.time()}
                            self.rttable.update_route(route)
                            self.trigledupdate(route)
                        elif port == rr['interface']:
                            self.rttable.update_route_time(rr)
                if flag == 1:
                    route={"dst": nr['ip'],
                           "metric": nr['metric'] + 1,
                           "gateway": source[0],
                           "interface": port,
                           "timer": time.time()}
                    self.rttable.add_route(route)
                    lroute = {"dst": route["dst"],
                              "gateway": route["gateway"],
                              "oif": route["interface"]}
                    self.rttable.apply_rip_route(lroute)
                    self.trigledupdate(route)


    def do_response(self, src, msg):
        print(src)
        print(msg)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        #fixme 520,but python doesn't support it
        sock.bind((src, 521))
        sock.sendto(msg, ('255.255.255.255', 520))
        sock.close()

    def recv(self, recvData, source):
        cmd = self.parser_packet_head(recvData[:8])
        if cmd == "REQUEST":
            self.request(source)
        elif cmd == "RESPONSE":
            self.response(recvData[8:], source)

    def run(self):
        while True:
            recvData, source = self.sock.recvfrom(65500)
            eventlet.spawn_n(self.recv, recvData, source)

rs = RipServer()
rs.run()
