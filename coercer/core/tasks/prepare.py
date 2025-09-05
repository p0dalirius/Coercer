#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : prepare.py
# Author             : Podalirius (@podalirius_) / p0rtL (@p0rtL6)
# Date created       : 3 Dec 2024

from coercer.structures.Modes import Modes


def prepare_tasks(available_methods, options, filter, mode, portmap=None):
    tasks = {}
    for method_type in available_methods.keys():
        for category in sorted(available_methods[method_type].keys()):
            for method in sorted(available_methods[method_type][category].keys()):
                instance = available_methods[method_type][category][method]["class"]

                if filter.method_matches_filter(instance):
                    for access_type, access_methods in instance.access.items():
                        if access_type not in tasks.keys():
                            tasks[access_type] = {}

                        # Access through SMB named pipe
                        if access_type == "ncan_np":
                            for access_method in access_methods:
                                namedpipe, uuid, version = (
                                    access_method["namedpipe"],
                                    access_method["uuid"],
                                    access_method["version"],
                                )
                                if filter.pipe_matches_filter(namedpipe):
                                    if mode == Modes.COERCE or mode == Modes.SCAN:
                                        if namedpipe not in tasks[access_type].keys():
                                            tasks[access_type][namedpipe] = {}

                                        if (
                                            uuid
                                            not in tasks[access_type][namedpipe].keys()
                                        ):
                                            tasks[access_type][namedpipe][uuid] = {}

                                        if (
                                            version
                                            not in tasks[access_type][namedpipe][
                                                uuid
                                            ].keys()
                                        ):
                                            tasks[access_type][namedpipe][uuid][
                                                version
                                            ] = []

                                        if (
                                            instance
                                            not in tasks[access_type][namedpipe][uuid][
                                                version
                                            ]
                                        ):
                                            tasks[access_type][namedpipe][uuid][
                                                version
                                            ].append(instance)

                                    elif mode == Modes.FUZZ:
                                        if uuid not in tasks[access_type].keys():
                                            tasks[access_type][uuid] = {}

                                        if (
                                            version
                                            not in tasks[access_type][uuid].keys()
                                        ):
                                            tasks[access_type][uuid][version] = []

                                        if (
                                            instance
                                            not in tasks[access_type][uuid][version]
                                        ):
                                            tasks[access_type][uuid][version].append(
                                                instance
                                            )

                        elif access_type == "ncacn_ip_tcp":
                            for access_method in access_methods:
                                uuid, version = (
                                    access_method["uuid"],
                                    access_method["version"],
                                )

                                if mode == Modes.COERCE or mode == Modes.SCAN:
                                    for port in options.dce_ports or portmap.get(
                                        "ncacn_ip_tcp", {}
                                    ).get("%s v%s" % (uuid.upper(), version), []):
                                        if port not in tasks[access_type].keys():
                                            tasks[access_type][port] = {}

                                        if uuid not in tasks[access_type][port].keys():
                                            tasks[access_type][port][uuid] = {}

                                        if (
                                            version
                                            not in tasks[access_type][port][uuid].keys()
                                        ):
                                            tasks[access_type][port][uuid][version] = []

                                        if (
                                            instance
                                            not in tasks[access_type][port][uuid][
                                                version
                                            ]
                                        ):
                                            tasks[access_type][port][uuid][
                                                version
                                            ].append(instance)

                                elif mode == Modes.FUZZ:
                                    if uuid not in tasks[access_type].keys():
                                        tasks[access_type][uuid] = {}

                                    if version not in tasks[access_type][uuid].keys():
                                        tasks[access_type][uuid][version] = []

                                    if (
                                        instance
                                        not in tasks[access_type][uuid][version]
                                    ):
                                        tasks[access_type][uuid][version].append(
                                            instance
                                        )
    return tasks
