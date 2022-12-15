#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Listener.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

import socket
import time
from coercer.structures.TestResult import TestResult


class Listener(object):
    """
    class Listener
    """

    def __init__(self, options, listen_ip=None, timeout=None):
        super(Listener, self).__init__()

        self.options = options

        if self.options.mode in ["fuzz", "scan"]:
            self.smb_port = self.options.smb_port
        elif self.options.mode in ["coerce"]:
            self.smb_port = self.options.smb_port

        self.timeout = 1
        self.listen_ip = "0.0.0.0"

        if listen_ip is not None:
            self.listen_ip = listen_ip

        if timeout is not None:
            self.timeout = timeout

    def start_smb(self, control_structure):
        """
        Function start_smb(self, control_structure)
        """
        start_time = int(time.time())
        stop_time = start_time + self.timeout
        while (int(time.time()) < stop_time) and control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.bind((self.listen_ip, self.smb_port))
                s.listen(5)
                conn, address = s.accept()
                data = conn.recv(2048)
                # Win11 2208:  b'\x00\x00\x00E\xffSMBr\x00\x00\x00\x00\x18S\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00\x00"\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
                # WinServ2016: b'\x00\x00\x00\x9b\xffSMBr\x00'
                # b'\x00\x00\x00\xfc\xfeSMB@\x00\x01\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x05\x00\x02\x00\x00\x00\x7f\x00\x00\x00\x12\xe3\x9f\x90\xfa7\xed\x11\x98.\xe8\xd8\xd1\xf3/\xf9p\x00\x00\x00\x05\x00\x00\x00\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\xec-\xd9\x94\xf2{D\x91\xd54\xb48KW\xbe\x81uM&\xbd.q\xff\xc3\xcb\x90\x87\x11\x1c\xbd9\xd8\x00\x00\x02\x00\x06\x00\x00\x00\x00\x00\x02\x00\x02\x00\x01\x00\x00\x00\x03\x00\x10\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x04\x00\x02\x00\x03\x00\x01\x00\x05\x00\x1a\x00\x00\x00\x00\x00F\x00R\x00T\x00L\x00S\x00E\x00Q\x00P\x00R\x00N\x00P\x000\x001\x00\x00\x00\x00\x00\x00\x00\x06
                if data.startswith(b'\x00\x00\x00') and b'SMB' in data:
                    # TODO: Handle SMB handshake better than this.
                    control_structure["result"] = TestResult.SMB_AUTH_RECEIVED
                else:
                    print("\n", data)
            except Exception as e:
                pass

    def start_http(self, control_structure, http_port=80):
        """
        Function start_http(self, control_structure, http_port=80)
        """
        start_time = int(time.time())
        stop_time = start_time + self.timeout
        while (int(time.time()) < stop_time) and control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if self.options.mode in ["fuzz", "scan"]:
                    s.bind((self.listen_ip, http_port))
                elif self.options.mode in ["coerce"]:
                    s.bind((self.listen_ip, self.options.http_port))
                s.listen(5)
                conn, address = s.accept()
                data = conn.recv(2048)
                # print("\n",data,"\n")
                if b'HTTP' in data:
                    control_structure["result"] = TestResult.HTTP_AUTH_RECEIVED
            except Exception as e:
                pass

