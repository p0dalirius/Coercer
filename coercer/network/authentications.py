#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : authentications.py
# Author             : Podalirius (@podalirius_)
# Date created       : 21 Sep 2022


from coercer.structures.TestResult import TestResult
from concurrent.futures import ThreadPoolExecutor
from coercer.network.Listener import Listener
import time


def trigger_and_catch_authentication(options, dcerpc_session, target, method_trigger_function, listenertype, listen_ip=None, http_port=80):
    """

    """
    listenertype = listenertype.lower()
    if listenertype not in ["smb", "http"]:
        print("[!] Unknown listener type '%s'" % listenertype)
        return False
    else:
        control_structure = {"result": TestResult.NO_AUTH_RECEIVED}
        # Waits for all the threads to be completed

        with ThreadPoolExecutor(max_workers=3) as tp:
            listener_instance = Listener(options=options, listen_ip=listen_ip)

            if listenertype == "smb":
                # print("[debug] Created smb listener")
                tp.submit(listener_instance.start_smb, control_structure)

            elif listenertype == "http":
                # print("[debug] Created http listener")
                tp.submit(listener_instance.start_http, control_structure, http_port=http_port)

            time.sleep(0.25)
            result_trigger = tp.submit(method_trigger_function, dcerpc_session, target)

        if control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
            if "rpc_x_bad_stub_data" in str(result_trigger._result):
                control_structure["result"] = TestResult.RPC_X_BAD_STUB_DATA

            elif "nca_s_unk_if" in str(result_trigger._result):
                control_structure["result"] = TestResult.NCA_S_UNK_IF

            elif "rpc_s_access_denied" in str(result_trigger._result):
                control_structure["result"] = TestResult.RPC_S_ACCESS_DENIED

            elif "ERROR_BAD_NETPATH" in str(result_trigger._result):
                control_structure["result"] = TestResult.ERROR_BAD_NETPATH

            elif "ERROR_INVALID_NAME" in str(result_trigger._result):
                control_structure["result"] = TestResult.ERROR_INVALID_NAME

            elif "STATUS_PIPE_DISCONNECTED" in str(result_trigger._result):
                control_structure["result"] = TestResult.SMB_STATUS_PIPE_DISCONNECTED

            elif "RPC_S_INVALID_BINDING" in str(result_trigger._result):
                control_structure["result"] = TestResult.RPC_S_INVALID_BINDING

            elif "RPC_S_INVALID_NET_ADDR" in str(result_trigger._result):
                control_structure["result"] = TestResult.RPC_S_INVALID_NET_ADDR

        return control_structure["result"]


def trigger_authentication(dcerpc_session, target, method_trigger_function):
    """

    """
    control_structure = {"result": TestResult.NO_AUTH_RECEIVED}

    result_trigger = method_trigger_function(dcerpc_session, target)

    if control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
        if "rpc_x_bad_stub_data" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_X_BAD_STUB_DATA

        elif "nca_s_unk_if" in str(result_trigger):
            control_structure["result"] = TestResult.NCA_S_UNK_IF

        elif "rpc_s_access_denied" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_S_ACCESS_DENIED

        elif "ERROR_BAD_NETPATH" in str(result_trigger):
            control_structure["result"] = TestResult.ERROR_BAD_NETPATH

        elif "ERROR_INVALID_NAME" in str(result_trigger):
            control_structure["result"] = TestResult.ERROR_INVALID_NAME

        elif "STATUS_PIPE_DISCONNECTED" in str(result_trigger):
            control_structure["result"] = TestResult.SMB_STATUS_PIPE_DISCONNECTED

        elif "RPC_S_INVALID_BINDING" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_S_INVALID_BINDING

        elif "RPC_S_INVALID_NET_ADDR" in str(result_trigger):
            control_structure["result"] = TestResult.RPC_S_INVALID_NET_ADDR

    return control_structure["result"]