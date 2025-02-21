#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DCERPCSession.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

import sys
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from coercer.structures import EscapeCodes
from coercer.core.Reporter import reporter

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

    def connect_ncacn_ip_tcp(self, target, port, targetIp=None):
        self.target = target
        ncacn_ip_tcp = r'ncacn_ip_tcp:%s[%d]' % (target, port)
        self.__rpctransport = transport.DCERPCTransportFactory(ncacn_ip_tcp)
        self.session = self.__rpctransport.get_dce_rpc()
        self.session.set_credentials(self.credentials.username, self.credentials.password, self.credentials.domain, self.credentials.lmhash, self.credentials.nthash, None)
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        
        reporter.print_in_progress("Connecting to %s ... " % ncacn_ip_tcp, prefix="   ", end="", debug=True)
        try:
            self.session.connect()
        except Exception as e:
            reporter.print(("fail", EscapeCodes.BOLD_BRIGHT_RED), debug=True)
            reporter.print_error("Something went wrong, check error status => %s" % str(e), prefix="      ", debug=True)
            return None
        else:
            reporter.print(("success", EscapeCodes.BOLD_BRIGHT_GREEN), debug=True)
        return self.session

    def connect_ncacn_np(self, target, pipe, targetIp=None):
        """

        """
        self.target = target
        ncan_target = r'ncacn_np:%s[%s]' % (target, pipe)
        self.__rpctransport = transport.DCERPCTransportFactory(ncan_target)

        debug = False

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(
                username=self.credentials.username,
                password=self.credentials.password,
                domain=self.credentials.domain,
                lmhash=self.credentials.lmhash,
                nthash=self.credentials.nthash
            )

        if self.credentials.doKerberos == True:
            self.__rpctransport.set_kerberos(self.credentials.doKerberos, kdcHost=self.credentials.kdcHost)
        if targetIp is not None:
            self.__rpctransport.setRemoteHost(targetIp)

        self.session = self.__rpctransport.get_dce_rpc()
        self.session.set_auth_type(RPC_C_AUTHN_WINNT)
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        # Connecting to named pipe
        reporter.print_in_progress("Connecting to %s ... " % ncan_target, prefix="   ", end="", debug=True)
        try:
            self.session.connect()
        except Exception as e:
            reporter.print(("fail", EscapeCodes.BOLD_BRIGHT_RED), debug=True)
            reporter.print_error("Something went wrong, check error status => %s" % str(e), prefix="      ", debug=True)
            return None
        else:
            reporter.print(("success", EscapeCodes.BOLD_BRIGHT_GREEN), debug=True)
        return self.session

    def bind(self, interface_uuid, interface_version):
        """

        """
        # Binding to interface
        reporter.print_in_progress("Binding to interface <uuid='%s', version='%s'> ... " % (interface_uuid, interface_version), prefix="   ", end="", debug=True)
        try:
            self.session.bind(uuidtup_to_bin((interface_uuid, interface_version)))
        except Exception as e:
            reporter.print(("fail", EscapeCodes.BOLD_BRIGHT_RED), debug=True)
            reporter.print_error("Something went wrong, check error status => %s" % str(e), prefix="      ", debug=True)
            return False
        else:
            reporter.print(("success", EscapeCodes.BOLD_BRIGHT_GREEN), debug=True)
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