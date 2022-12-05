#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022

import socket
import fcntl
import struct


def get_ip_address_of_interface(ifname):
    """
    Function get_ip_address_of_interface(ifname)
    """
    if type(ifname) == str:
        ifname = bytes(ifname, "utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SIOCGIFADDR = 0x8915
    try:
        ifname = struct.pack('256s', ifname[:15])
        a = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifname)[20:24]
        return socket.inet_ntoa(a)
    except OSError as e:
        return None


def get_ip_address_to_target_remote_host(host, port):
    """
    Function get_ip_address_to_target_remote_host(host, port)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except Exception as e:
        return None


def can_listen_on_port(listen_ip, port):
    """
    Function can_listen_on_port(listen_ip, port)
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.bind((listen_ip, port))
        s.listen(5)
        s.close()
        return True
    except OSError as e:
        return False


def get_ip_addr_to_listen_on(target, options):
    """
    Function get_ip_addr_to_listen_on(target, options)
    """
    # Getting IP address to listen on
    listening_ip = None
    if options.ip_address is not None:
        listening_ip = options.ip_address
    elif options.interface is not None:
        listening_ip = get_ip_address_of_interface(options.interface)
        if listening_ip is None:
            print("[!] Could not get IP address of interface '%s'" % options.interface)
    else:
        # Getting ip address of interface that can access remote target
        possible_ports, k = [445, 139, 88], 0
        while listening_ip is None and k < len(possible_ports):
            listening_ip = get_ip_address_to_target_remote_host(target, possible_ports[k])
            k += 1
        if listening_ip is None:
            print("[!] Could not detect interface with a route to target machine '%s'" % target)
    return listening_ip


def get_next_http_listener_port(current_value, listen_ip, options):
    """
    Function get_next_http_listener_port(current_value, listen_ip, options)
    """
    port_window = (options.max_http_port - options.min_http_port)

    if current_value > options.max_http_port:
        current_value = options.max_http_port

    if current_value < options.min_http_port:
        current_value = options.min_http_port

    current_value = options.min_http_port + ((current_value + 1) % port_window)
    while not can_listen_on_port(listen_ip, current_value):
        current_value = options.min_http_port + ((current_value + 1) % port_window)

    return current_value
