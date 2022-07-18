#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RPCProtocol.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022


import sys
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return '[!] SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return '[!] SessionError: unknown error code: 0x%x' % self.error_code


class RPCProtocol(object):
    """
    Documentation for class RPCProtocol
    """

    uuid = None
    version = None

    auth_type = None
    auth_level = None
    pipe = None

    available_pipes = []

    webdav_host = None
    webdav_port = None

    ncan_target = None
    __rpctransport = None
    dce = None
    verbose = False
    debug = False

    def __init__(self, verbose=False):
        super(RPCProtocol, self).__init__()
        self.verbose = verbose

    def connect(self, username, password, domain, lmhash, nthash, target, dcHost, doKerberos=False, targetIp=None):
        self.ncan_target = r'ncacn_np:%s[%s]' % (target, self.pipe)
        self.__rpctransport = transport.DCERPCTransportFactory(self.ncan_target)

        self.auth_username = username
        self.auth_password = password
        self.auth_domain = domain
        self.target = target
        self.auth_lmhash = lmhash
        self.auth_nthash = nthash

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash
            )

        if doKerberos == True:
            self.__rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp is not None:
            self.__rpctransport.setRemoteHost(targetIp)

        self.dce = self.__rpctransport.get_dce_rpc()
        if self.auth_type is not None:
            self.dce.set_auth_type(self.auth_type)
        if self.auth_level is not None:
            self.dce.set_auth_level(self.auth_level)

        if self.verbose:
            print("         [>] Connecting to %s ... " % self.ncan_target, end="")
        sys.stdout.flush()
        try:
            self.dce.connect()
        except Exception as e:
            if self.verbose:
                print("\x1b[1;91mfail\x1b[0m")
                print("         [!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            if self.verbose:
                print("\x1b[1;92msuccess\x1b[0m")

        if self.verbose:
            print("         [>] Binding to <uuid='%s', version='%s'> ... " % (self.uuid, self.version), end="")
        sys.stdout.flush()
        try:
            self.dce.bind(uuidtup_to_bin((self.uuid, self.version)))
        except Exception as e:
            if self.verbose:
                print("\x1b[1;91mfail\x1b[0m")
                print("         [!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            if self.verbose:
                print("\x1b[1;92msuccess\x1b[0m")

        return True

    @classmethod
    def list_coerce_methods(cls):
        return []

    def perform_coerce_calls(self, listener):
        pass

    def analyze_coerce_calls(self, listener):
        pass