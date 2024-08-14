#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022

import socket
import sys
import struct
from platform import uname


def get_ip_address_of_interface(ifname):
    """
    Function get_ip_address_of_interface(ifname)

    This function retrieves the IP address of a specified network interface.

    Parameters:
    - ifname (str): The name of the network interface.

    Returns:
    - str: The IP address of the specified network interface.
    """

    if sys.platform == "win32":
        return None

    elif sys.platform == "linux" and "microsoft" not in uname().release.lower() and "microsoft" not in uname().version.lower():
        import fcntl
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

    else:
        return None


def get_ip_address_to_target_remote_host(host, port):
    """
    Function get_ip_address_to_target_remote_host(host, port)

    This function attempts to connect to a remote host on a specified port and returns the IP address of the local interface used for the connection.

    Parameters:
    - host (str): The hostname or IP address of the remote host.
    - port (int): The port number to connect to on the remote host.

    Returns:
    - str: The IP address of the local interface used for the connection, or None if the connection fails.
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

    This function checks if a specified IP address and port can be used for listening.

    Parameters:
    - listen_ip (str): The IP address to check for listening.
    - port (int): The port number to check for listening.

    Returns:
    - bool: True if the IP address and port can be used for listening, False otherwise.
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

    This function determines the IP address to use for listening based on the provided options.

    Parameters:
    - target (str): The target machine or IP address to consider for IP address selection.
    - options (object): An object containing options for IP address selection, including:
        - ip_address (str): A specific IP address to use for listening.
        - interface (str): The network interface to use for listening.
        - min_http_port (int): The minimum HTTP port number to consider for listening.
        - max_http_port (int): The maximum HTTP port number to consider for listening.

    Returns:
    - str: The IP address to use for listening, or None if no suitable IP address is found.
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

    This function determines the next available HTTP port to use for listening based on the current value and options provided.

    Parameters:
    - current_value (int): The current port number to consider for listening.
    - listen_ip (str): The IP address to use for listening.
    - options (object): An object containing options for port selection, including:
        - min_http_port (int): The minimum HTTP port number to consider for listening.
        - max_http_port (int): The maximum HTTP port number to consider for listening.

    Returns:
    - int: The next available HTTP port to use for listening within the specified range.
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
