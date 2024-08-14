#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DCERPCSession.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

import sys
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class DCERPCSession(object):
    """
    Documentation for class DCERPCSession
    """

    __rpctransport = None
    session = None
    target = None

    def __init__(self, credentials, verbose=False):
        super(DCERPCSession, self).__init__()
        self.__verbose = True
        self.credentials = credentials

    def connect_ncacn_ip_tcp(self, target, port, targetIp=None, debug=False):
        """
        Connects to a target system over the NCACN IP TCP transport protocol.

        This method establishes a connection to a target system using the NCACN IP TCP transport protocol. It sets up the necessary credentials, authentication, and encryption for the connection.

        Parameters:
        - target (str): The hostname or IP address of the target system.
        - port (int): The port number to connect to on the target system.
        - targetIp (str, optional): The IP address of the target system. Defaults to None.
        - debug (bool, optional): Enables or disables debug output. Defaults to False.
        """

        self.target = target
        ncacn_ip_tcp = r'ncacn_ip_tcp:%s[%d]' % (target, port)

        self.__rpctransport = transport.DCERPCTransportFactory(ncacn_ip_tcp)
        self.session = self.__rpctransport.get_dce_rpc()

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.session.set_credentials(
                username=self.credentials.username, 
                password=self.credentials.password, 
                domain=self.credentials.domain, 
                lmhash=self.credentials.lm_hex, 
                nthash=self.credentials.nt_hex, 
                aesKey=self.credentials.aesKey,
                TGT=None,
                TGS=None
            )

        if self.credentials.use_kerberos == True:
            self.__rpctransport.set_kerberos(self.credentials.use_kerberos, kdcHost=self.credentials.kdcHost)
        
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        if debug:
            print("   [>] Connecting to %s ... " % ncacn_ip_tcp, end="")
            sys.stdout.flush()
        try:
            self.session.connect()
        except Exception as e:
            if debug:
                print("\x1b[1;91mfail\x1b[0m")
                print("      [!] Something went wrong, check error status => %s" % str(e))
            return None
        else:
            if debug:
                print("\x1b[1;92msuccess\x1b[0m")
        return self.session

    def connect_ncacn_np(self, target, pipe, targetIp=None, debug=False):
        """
        Connects to a named pipe over the NCACN NP transport protocol.

        This method establishes a connection to a named pipe on a remote system using the NCACN NP transport protocol. It sets up the necessary credentials, authentication, and encryption for the connection.

        Parameters:
        - target (str): The hostname or IP address of the target system.
        - pipe (str): The name of the named pipe to connect to.
        - targetIp (str, optional): The IP address of the target system. Defaults to None.
        - debug (bool, optional): Enables or disables debug output. Defaults to False.

        Returns:
        - session (DCERPCSession): The established session object if the connection is successful, otherwise None.
        """

        self.target = target
        ncan_target = r'ncacn_np:%s[%s]' % (target, pipe)
        self.__rpctransport = transport.DCERPCTransportFactory(ncan_target)

        if hasattr(self.__rpctransport, "set_credentials"):
            self.__rpctransport.set_credentials(
                username=self.credentials.username,
                password=self.credentials.password,
                domain=self.credentials.domain,
                lmhash=self.credentials.lm_hex,
                nthash=self.credentials.nt_hex,
                aesKey=self.credentials.aesKey,
                TGT=None,
                TGS=None
            )

        if self.credentials.use_kerberos == True:
            self.__rpctransport.set_kerberos(self.credentials.use_kerberos, kdcHost=self.credentials.kdcHost)
        if targetIp is not None:
            self.__rpctransport.setRemoteHost(targetIp)

        self.session = self.__rpctransport.get_dce_rpc()
        
        self.session.set_auth_type(RPC_C_AUTHN_WINNT)
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        # Connecting to named pipe
        if debug:
            print("   [>] Connecting to %s ... " % ncan_target, end="")
            sys.stdout.flush()
        try:
            self.session.connect()
        except Exception as e:
            if debug:
                print("\x1b[1;91mfail\x1b[0m")
                print("      [!] Something went wrong, check error status => %s" % str(e))
            return None
        else:
            if debug:
                print("\x1b[1;92msuccess\x1b[0m")
        return self.session

    def bind(self, interface_uuid, interface_version, debug=False):
        """
        bind(interface_uuid, interface_version, debug=False)

        Binds to a specific interface on the remote server.

        Parameters:
        - interface_uuid (str): The UUID of the interface to bind to.
        - interface_version (str): The version of the interface to bind to.
        - debug (bool, optional): Enables or disables debug output. Defaults to False.

        Returns:
        - bool: True if the binding was successful, otherwise False.
        """

        # Binding to interface
        if debug:
            print("   [>] Binding to interface <uuid='%s', version='%s'> ... " % (interface_uuid, interface_version), end="")
            sys.stdout.flush()
        try:
            self.session.bind(uuidtup_to_bin((interface_uuid, interface_version)))
        except Exception as e:
            if debug:
                print("\x1b[1;91mfail\x1b[0m")
                print("      [!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            if debug:
                print("\x1b[1;92msuccess\x1b[0m")
        return True

    def set_verbose(self, value):
        """
        set_verbose(value)

        Sets the current verbosity level
        """
        self.__verbose = value

    def get_verbose(self):
        """
        get_verbose()

        Gets the current verbosity level
        """
        return self.__verbose