#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Listener.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

from collections import namedtuple
import socket
import time
import threading
from coercer.structures.TestResult import TestResult


responder_options = dict(
    Domain='domain',
    Interface='ALL',
    ExternalIP=None,
    ExternalIP6=None,
    LM_On_Off=False,
    NOESS_On_Off=False,
    WPAD_On_Off=False,
    DHCP_On_Off=False,
    ProxyAuth_On_Off=False,
    DHCP_DNS=False,
    Basic=False,
    OURIP=None,
    Force_WPAD_Auth=False,
    Upstream_Proxy=None,
    Analyze=True,
    Verbose=False,
    )

ResponderOptions = namedtuple(
    'ResponderOptions',
    responder_options.keys(),
    )


def create_smb_server(control_structure, listen_ip, interface, lock):
    """Factory function for creating a SMBServer object"""

    def record_result(result):
        if control_structure["result"] in [
            TestResult.SMB_AUTH_RECEIVED_NTLMv1,
            TestResult.SMB_AUTH_RECEIVED_NTLMv2,
        ]:
            # Already handled; do nothing
            return

        print("[+] Authentication received: "
              "[%(module)s] %(type)s - %(user)s@%(client)s\n" % result)

        if result['type'] in ['NTLMv1', 'NTLMv1-SSP']:
            control_structure["result"] = TestResult.SMB_AUTH_RECEIVED_NTLMv1
        elif result['type'] in ['NTLMv2', 'NTLMv2-SSP']:
            control_structure["result"] = TestResult.SMB_AUTH_RECEIVED_NTLMv2
        else:
            return

        lock.release()
        # This should cause the responder loop to break
        raise Exception

    # Load Responder code
    from coercer.ext.responder import utils
    utils.color == str
    # Set responder settings
    from coercer.ext.responder import settings
    settings.init()
    responder_options.update(dict(ExternalIP=listen_ip, OURIP=listen_ip))
    responder_options.update(dict(Interface=interface))
    options = ResponderOptions(*responder_options.values())
    settings.Config.populate(options)
    from coercer.ext.responder import SMB
    from coercer.ext.responder import Responder
    # Monkeypatch SaveToDb
    # Note that this is an ugly hack equivalent to modifying a global variable.
    # This will prevent Coercer from parallelizing.
    SMB.SaveToDb = record_result

    class SMBServer(threading.Thread):
        def run(self_):
            # FIXME I wanted to bind to listen_ip, but that allows yields:
            #  'Address family for hostname not supported'
            self_.server = Responder.ThreadingTCPServer(('', 445), SMB.SMB1)
            self_.server.allow_reuse_address = True
            self_.server.serve_forever()

        def shutdown(self_):
            self_.server.shutdown()
            self_.server.server_close()

    lock.acquire()
    smb_server = SMBServer()
    return smb_server


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
        lock = threading.Lock()
        smb_server = create_smb_server(control_structure, self.listen_ip,
                                       self.options.interface or 'ALL', lock)
        smb_server.start()
        lock.acquire(timeout=self.timeout)
        smb_server.shutdown()

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

