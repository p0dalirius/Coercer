#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Sep 2022

import socket

import psutil

from coercer.core.Reporter import reporter


def get_ip_address_of_interface(ifname):
    """
    Function get_ip_address_of_interface(ifname)
    """
    return next(
        iter(
            [
                addr.address
                for addr in psutil.net_if_addrs().get(ifname, [])
                if addr.family == socket.AF_INET
            ]
        ),
        None,
    )


def get_ip_address_to_target_remote_host(host, port):
    """
    Function get_ip_address_to_target_remote_host(host, port)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except Exception:
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
    except OSError:
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
            reporter.print_error(
                "Could not get IP address of interface '%s'" % options.interface
            )
    else:
        # Getting ip address of interface that can access remote target
        possible_ports, k = [
            4445 if options.redirecting_smb_packets else options.smb_port,
            139,
            88,
        ], 0
        while listening_ip is None and k < len(possible_ports):
            listening_ip = get_ip_address_to_target_remote_host(
                target, possible_ports[k]
            )
            k += 1
        if listening_ip is None:
            reporter.print_error(
                "Could not detect interface with a route to target machine '%s'"
                % target
            )
    return listening_ip


def get_next_http_listener_port(current_value, listen_ip, options):
    """
    Function get_next_http_listener_port(current_value, listen_ip, options)
    """
    port_window = options.max_http_port - options.min_http_port

    if current_value > options.max_http_port:
        current_value = options.max_http_port

    if current_value < options.min_http_port:
        current_value = options.min_http_port

    current_value = options.min_http_port + ((current_value + 1) % port_window)
    while not can_listen_on_port(listen_ip, current_value):
        current_value = options.min_http_port + ((current_value + 1) % port_window)

    return current_value


def redirect_smb_packets():
    import pydivert

    with pydivert.WinDivert("tcp.DstPort == 445 or tcp.SrcPort == 4445") as w:
        for packet in w:
            if packet.dst_port == 445 and packet.is_inbound:
                packet.dst_port = 4445
            if packet.src_port == 4445 and packet.is_outbound:
                packet.src_port = 445
            w.send(packet)
