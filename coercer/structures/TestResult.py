#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : TestResults.py
# Author             : Podalirius (@podalirius_)
# Date created       : 19 Sep 2022

from enum import Enum


class TestResult(Enum):
    """
    Enum class TestResult
    """
    NO_AUTH_RECEIVED   = 0x0
    SMB_AUTH_RECEIVED  = 0x1
    HTTP_AUTH_RECEIVED = 0x2
    SMB_AUTH_RECEIVED_NTLMv1  = 0x3
    SMB_AUTH_RECEIVED_NTLMv2  = 0x4

    NCA_S_UNK_IF = 0x10001

    ERROR_BAD_NETPATH = 0x35
    ERROR_INVALID_NAME = 0x7b

    RPC_X_BAD_STUB_DATA = 0x20001
    RPC_S_ACCESS_DENIED = 0x5
    RPC_S_INVALID_BINDING = 0x6a6
    RPC_S_INVALID_NET_ADDR = 0x6ab

    SMB_STATUS_PIPE_DISCONNECTED = 0x30001

    @staticmethod
    def from_string(string):
        if "rpc_x_bad_stub_data" in string:
            return TestResult.RPC_X_BAD_STUB_DATA

        elif "nca_s_unk_if" in string:
            return TestResult.NCA_S_UNK_IF

        elif "rpc_s_access_denied" in string:
            return TestResult.RPC_S_ACCESS_DENIED

        elif "ERROR_BAD_NETPATH" in string:
            return TestResult.ERROR_BAD_NETPATH

        elif "ERROR_INVALID_NAME" in string:
            return TestResult.ERROR_INVALID_NAME

        elif "STATUS_PIPE_DISCONNECTED" in string:
            return TestResult.SMB_STATUS_PIPE_DISCONNECTED

        elif "RPC_S_INVALID_BINDING" in string:
            return TestResult.RPC_S_INVALID_BINDING

        elif "RPC_S_INVALID_NET_ADDR" in string:
            return TestResult.RPC_S_INVALID_NET_ADDR

        else:
            raise ValueError("Cannot convert string to enum => %s" % string)