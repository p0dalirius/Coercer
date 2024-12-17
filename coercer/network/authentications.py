#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : authentications.py
# Author             : Podalirius (@podalirius_)
# Date created       : 21 Sep 2022


from coercer.structures.TestResult import TestResult
from concurrent.futures import ThreadPoolExecutor
from coercer.network.Listener import Listener
import time

from coercer.core.Reporter import reporter

def trigger_and_catch_authentication(options, dcerpc_session, target, method_trigger_function, listenertype, listen_ip=None, http_port=80):
    """

    """
    listenertype = listenertype.lower()
    if listenertype not in ["smb", "http"]:
        reporter.print_error("Unknown listener type '%s'" % listenertype)
        return False
    else:
        control_structure = {"result": TestResult.NO_AUTH_RECEIVED}
        # Waits for all the threads to be completed

        with ThreadPoolExecutor(max_workers=3) as tp:
            listener_instance = Listener(options=options, listen_ip=listen_ip)

            if listenertype == "smb":
                reporter.print_info("Created smb listener", debug=True)
                tp.submit(listener_instance.start_smb, control_structure)

            elif listenertype == "http":
                reporter.print_info("Created http listener", debug=True)
                tp.submit(listener_instance.start_http, control_structure, http_port=http_port)

            time.sleep(0.25)
            result_trigger = tp.submit(method_trigger_function, dcerpc_session, target)

        if control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
            control_structure["result"] = TestResult.from_string(str(result_trigger._result))

        return control_structure["result"]


def trigger_authentication(dcerpc_session, target, method_trigger_function):
    """

    """
    control_structure = {"result": TestResult.NO_AUTH_RECEIVED}

    result_trigger = method_trigger_function(dcerpc_session, target)

    if control_structure["result"] == TestResult.NO_AUTH_RECEIVED:
        control_structure["result"] = TestResult.from_string(str(result_trigger))
        
    return control_structure["result"]
