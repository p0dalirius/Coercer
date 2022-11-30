#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : loader.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 Sep 2022


import os
import sys
from importlib import import_module
from coercer.structures.MethodType import MethodType


def find_and_load_coerce_methods(debug=False):
    """
    Function find_and_load_coerce_methods()

    Parameters:
        bool:debug Enable or disable debug output

    Returns:
        list:coerce_methods
    """
    coerce_methods = {}
    search_dir = os.path.dirname(__file__) + os.path.sep + ".." + os.path.sep + "methods"
    if debug:
        print("[loader] Loading coerce methods from %s ..." % search_dir)
    sys.path.extend([search_dir])
    for _dir in os.listdir(search_dir):
        _dirpath = search_dir + os.path.sep + _dir
        if os.path.isdir(_dirpath) and _dir not in ["__pycache__"]:
            if debug:
                print("[loader] Loading methods for category %s ..." % _dir)
            for _file in os.listdir(_dirpath):
                _filepath = _dirpath + os.path.sep + _file
                if _file.endswith('.py'):
                    if os.path.isfile(_filepath) and _file not in ["__init__.py"]:
                        try:
                            module = import_module('coercer.methods.%s.%s' % (_dir, _file[:-3]))
                            method_class = module.__getattribute__(_file[:-3])
                            if all([kw in dir(method_class) for kw in ["method_type"]]):
                                if method_class.method_type not in coerce_methods.keys():
                                    coerce_methods[method_class.method_type] = {}
                                # Handling Microsoft Network protocols methods
                                if method_class.method_type == MethodType.MICROSOFT_PROTOCOL:
                                    if method_class.protocol["shortname"] not in coerce_methods[method_class.method_type].keys():
                                        coerce_methods[method_class.method_type][method_class.protocol["shortname"]] = {}
                                    if method_class.function["name"] not in coerce_methods[method_class.method_type][method_class.protocol["shortname"]].keys():
                                        coerce_methods[method_class.method_type][method_class.protocol["shortname"]][method_class.function["name"]] = {
                                            "class": method_class
                                        }
                                    if debug:
                                        print("[loader]   └──> Loaded Remote Procedure Call %s (opnum %d)" % (method_class.function["name"], method_class.function["opnum"]))
                                # Handling other methods
                                elif method_class.method_type == MethodType.OTHER:
                                    pass
                            else:
                                if debug:
                                    print("[loader] '%s' does not match the template." % _file)
                        except AttributeError as e:
                            pass
    if debug:
        print("[loader] coerce_methods:", coerce_methods)
    return coerce_methods
