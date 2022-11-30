#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MSPROTOCOLRPCCALL.py
# Author             : Podalirius (@podalirius_)
# Date created       : 16 Sep 2022

import jinja2
from coercer.structures.MethodType import MethodType


class MSPROTOCOLRPCCALL(object):
    """
    Documentation for class MSPROTOCOLRPCCALL
    """

    method_type = MethodType.MICROSOFT_PROTOCOL

    exploit_paths = []

    path = None

    protocol = {
        "longname": "",
        "shortname": ""
    }

    function = {
        "name": "",
        "opnum": 0
    }

    def __init__(self, path):
        super(MSPROTOCOLRPCCALL, self).__init__()
        self.path = path
        
    def __str__(self):
        parameters = []
        from sys import platform
        if platform == "linux" or platform == "linux2":
            # linux
            function_template = "%s──>\x1b[96m%s\x1b[0m(%s)"
            parameter_template = "\x1b[94m%s\x1b[0m=\x1b[93m%s\x1b[0m"
        elif platform == "darwin":
            # OS X
            function_template = "%s──>%s(%s)"
            parameter_template = "\x1b[94m%s\x1b[0m=\x1b[93m%s\x1b[0m"
        elif platform == "win32":
            # Windows...
            function_template = "%s──>%s(%s)"
            parameter_template = "%s=%s"


        for arg in self.function["vulnerable_arguments"]:
            parameters.append(
                parameter_template % (
                    arg,
                    str(bytes(self.path, 'utf-8'))[1:].replace('\\\\', '\\')
                )
            )
        parameters = ', '.join(parameters)

        return function_template % (
            self.protocol["shortname"],
            self.function["name"],
            parameters
        )

    @classmethod
    def generate_exploit_templates(cls, desired_auth_type=None):
        paths = []
        for auth_type, exploit_path in cls.exploit_paths:
            if desired_auth_type is not None:
                if auth_type == desired_auth_type:
                    paths.append((auth_type, exploit_path))
            else:
                paths.append((auth_type, exploit_path))
        return paths

