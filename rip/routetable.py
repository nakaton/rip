#!/usr/bin/env python
# encoding: utf-8
from pyroute2 import IPDB
import time

class RtTable():
    def __init__(self):
        """
        rip_entry = [
        {'dst': '172.16.1.0/24',
         'metric': 1, #1-16
         'gateway': '172.16.1.2',
         'interface': 4,
         'timer': 0,
        }
        ]
        """
        self.rip_table = []
        self.direct_table = []
        self.ipdb = IPDB()
        self.get_direct_table()

    def get_direct_table(self):
        self.direct_table = [ x for x in self.ipdb.routes if x['family'] == 2 if x['prefsrc']]

    def apply_rip_route(self, route):
        """ route = {'dst': '172.16.1.0/24',
                     'oif': 4,
                     'gateway': '172.16.1.2',
        }
        """
        self.ipdb.routes.add(route).commit()

    def remove_rip_route(self, route):
        r = {'dst': route['dst'],
             'oif': route['interface'],
             'gateway': route['gateway']}
        self.ipdb.routes.remove(r).commit()

    def get_route(self, route):
        for r in self.rip_table:
            if r['dst'] == route['dst']:
                return r

    def add_route(self, route):
        self.rip_table.append(route)

    def update_route(self, route):
        self.remove_route(route)
        self.add_route(route)

    def remove_route(self, route):
        for r in self.rip_table:
            if r['dst'] == route['dst']:
                self.rip_table.remove(r)

    def get_all_route(self):
        return self.rip_table

    def update_route_time(self, route):
        for r in self.rip_table:
            if r['dst'] == route['dst']:
                r['timer'] = time.time()

