#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Reporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jul 2022

from functools import wraps
import sqlite3
import os
import json
import xlsxwriter
import sys
import logging
from coercer.models.MSPROTOCOLRPCCALL import MSPROTOCOLRPCCALL
from coercer.structures import EscapeCodes
from coercer.structures.TestResult import TestResult

def create_reporter(options, verbose):
    global reporter
    reporter = Reporter(options, verbose)

def should_print(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        verbose = kwargs.get("verbose", False)
        debug = kwargs.get("debug", False)

        if verbose and not self.options.verbose:
            return
        
        if debug and not self.options.debug:
            return
        
        return func(self, *args, **kwargs)
    return wrapper

def parse_print_args(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        prefix = kwargs.pop("prefix", None)

        if len(args) == 1:
            message = args[0]
        elif len(args) == 2:
            if prefix is None:
                prefix = args[0]
            message = args[1]
        else:
            raise Exception("Print function takes a maximum of two arguments.")

        return func(self, prefix, message, **kwargs)
    return wrapper

class Reporter(object):
    """
    Documentation for class Reporter
    """

    def __init__(self, options, verbose=False):
        super(Reporter, self).__init__()

        if options.log_file is not None:
            logging.basicConfig(filename=options.log_file, level=options.minimum_log_level, format='%(asctime)s %(levelname)s %(message)s')
            self.logger = logging.getLogger("coercer")
        else:
            self.logger = None

        self.options = options
        self.verbose = verbose
        self.test_results = {}

    # Args can be strings, or tuples (string, escape code)
    @should_print
    def print(self, *args, **kwargs):
        prefix = kwargs.get("prefix", None)
        symbol_arg = kwargs.get("symbol", None)
        symbol_bold = kwargs.get("symbol_bold", True)
        end = kwargs.get("end", "\n")

        if self.logger is not None:
            debug = kwargs.get("debug", False)
            log_level = kwargs.get("log_level", logging.DEBUG if debug else logging.INFO)
            log_string = ""

        output_string = ""

        if prefix:
            output_string += prefix

        if symbol_arg:
            if isinstance(symbol_arg, tuple):
                symbol = symbol_arg[0]
                if len(symbol_arg) == 2:
                    symbol_color = symbol_arg[1]
                else:
                    symbol_color = None
            else:
                symbol = symbol_arg
                symbol_color = None

            if self.logger is not None:
                log_string += "[%s] " % symbol

            if self.options.disable_escape_codes:
                output_string += "[%s] " % symbol
            else:
                if symbol_bold:
                    output_string += EscapeCodes.BOLD
                
                output_string += "["

                if symbol_color:
                    output_string += symbol_color + symbol + EscapeCodes.RESET
                else:
                    output_string += symbol
                
                if symbol_bold:
                    output_string += EscapeCodes.BOLD

                output_string += "]"

                if symbol_bold:
                    output_string += EscapeCodes.RESET
            
            output_string += " "

        for arg in args:
            if isinstance(arg, tuple):
                if not self.options.disable_escape_codes:
                    output_string += arg[1]

                if issubclass(type(arg[0]), MSPROTOCOLRPCCALL):
                    output_arg = arg[0].to_string(self.options.disable_escape_codes)
                    log_arg = arg[0].to_string(True)
                else:
                    output_arg = str(arg[0])
                    log_arg = output_arg

                output_string += output_arg

                if self.logger is not None:
                    log_string += log_arg

                if not self.options.disable_escape_codes:
                    output_string += EscapeCodes.RESET
            else:
                if issubclass(type(arg), MSPROTOCOLRPCCALL):
                    output_arg = arg.to_string(self.options.disable_escape_codes)
                    log_arg = arg.to_string(True)
                else:
                    output_arg = str(arg)
                    log_arg = output_arg

                output_string += output_arg
                if self.logger is not None:
                    log_string += log_arg
        
        if self.logger is not None:
            self.logger.log(level=log_level, msg=log_string)
        
        print(output_string, end=end)
        sys.stdout.flush()

    def print_testing(self, msprotocol_rpc_instance, **kwargs):
        self.print("(", ("-testing-", EscapeCodes.BRIGHT_YELLOW), ") ", msprotocol_rpc_instance, prefix="      ", symbol=(">", EscapeCodes.BRIGHT_YELLOW), **kwargs)

    @parse_print_args
    def print_in_progress(self, prefix, message, **kwargs):
        self.print(message, prefix=prefix, symbol=(">", EscapeCodes.BRIGHT_YELLOW), **kwargs)
        
    @parse_print_args
    def print_info(self, prefix, message, **kwargs):
        self.print(message, prefix=prefix, symbol=("info", EscapeCodes.BRIGHT_GREEN), **kwargs)

    @parse_print_args
    def print_ok(self, prefix, message, **kwargs):
        self.print(message, prefix=prefix, symbol=("+", EscapeCodes.BRIGHT_GREEN), **kwargs)

    @parse_print_args
    def print_warn(self, prefix, message, **kwargs):
        self.print(message, prefix=prefix, symbol=("warn", EscapeCodes.BRIGHT_RED), log_level=logging.WARN **kwargs)
    
    @parse_print_args
    def print_error(self, prefix, message, **kwargs):
        self.print(message, prefix=prefix, symbol=("!", EscapeCodes.BRIGHT_RED), log_level=logging.ERROR, **kwargs)

    def print_result(self, symbol, result, msprotocol_rpc_instance, escape_code=None, **kwargs):
        self.print("(", (result, escape_code), ") ", msprotocol_rpc_instance, prefix="      ", symbol=(symbol, escape_code), **kwargs)

    def report_test_result(self, target, uuid, version, namedpipe, msprotocol_rpc_instance, result, exploitpath):
        function_name = msprotocol_rpc_instance.function["name"]
        if target not in self.test_results.keys():
            self.test_results[target] = {}
        if uuid not in self.test_results[target].keys():
            self.test_results[target][uuid] = {}
        if version not in self.test_results[target][uuid].keys():
            self.test_results[target][uuid][version] = {}
        if function_name not in self.test_results[target][uuid][version].keys():
            self.test_results[target][uuid][version][function_name] = {}
        if namedpipe not in self.test_results[target][uuid][version][function_name].keys():
            self.test_results[target][uuid][version][function_name][namedpipe] = []

        # Save result to database
        self.test_results[target][uuid][version][function_name][namedpipe].append({
            "function": msprotocol_rpc_instance.function,
            "protocol": msprotocol_rpc_instance.protocol,
            "testresult": result.name,
            "exploitpath": exploitpath
        })

        if not self.options.disable_escape_codes:
            sys.stdout.write(EscapeCodes.CURSOR_UP_ONE)
            sys.stdout.write(EscapeCodes.ERASE_LINE)

        if self.options.mode in ["scan", "fuzz"]:
            if result == TestResult.SMB_AUTH_RECEIVED:
                self.print_result("+", "SMB Auth", msprotocol_rpc_instance, EscapeCodes.BOLD_BRIGHT_GREEN)
            elif result == TestResult.HTTP_AUTH_RECEIVED:
                self.print_result("+", "HTTP Auth", msprotocol_rpc_instance, EscapeCodes.BOLD_BRIGHT_GREEN)
            elif result == TestResult.NCA_S_UNK_IF:
                self.print_result("-", "-No Func-", msprotocol_rpc_instance, EscapeCodes.BOLD_BRIGHT_MAGENTA)
            else:
                if self.verbose:
                    self.print_result("!", result.name, msprotocol_rpc_instance, EscapeCodes.BOLD_BRIGHT_RED)
        elif self.options.mode in ["coerce"]:
            if result == TestResult.ERROR_BAD_NETPATH:
                self.print_result("+", "ERROR_BAD_NETPATH", msprotocol_rpc_instance, EscapeCodes.BOLD_BRIGHT_GREEN)
            else:
                if self.verbose:
                    self.print_result("!", result.name, msprotocol_rpc_instance, EscapeCodes.BOLD_BRIGHT_RED)

    def exportXLSX(self, filename):
        basepath = os.path.dirname(filename)
        filename = os.path.basename(filename)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        # export

        workbook = xlsxwriter.Workbook(path_to_file)
        worksheet = workbook.add_worksheet()

        header_format = workbook.add_format({'bold': 1})
        header_fields = ["Target", "Interface UUID", "Interface version", "SMB named pipe", "Protocol long name", "Protocol short name", "RPC function name", "Operation number", "Result", "Working path"]
        for k in range(len(header_fields)):
            worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
        worksheet.set_row(0, 60, header_format)
        worksheet.write_row(0, 0, header_fields)

        row_id = 1
        for target in self.test_results.keys():
            for uuid in self.test_results[target].keys():
                for version in self.test_results[target][uuid].keys():
                    for function_name in self.test_results[target][uuid][version].keys():
                        for namedpipe in self.test_results[target][uuid][version][function_name].keys():
                            for test_result in self.test_results[target][uuid][version][function_name][namedpipe]:
                                data = [target, uuid, version, namedpipe, test_result["protocol"]["longname"], test_result["protocol"]["shortname"], test_result["function"]["name"], test_result["function"]["opnum"], test_result["testresult"], test_result["exploitpath"]]
                                worksheet.write_row(row_id, 0, data)
                                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()
        self.print_info("Results exported to XLSX in '%s'" % path_to_file)

    def exportJSON(self, filename):
        basepath = os.path.dirname(filename)
        filename = os.path.basename(filename)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        # export
        f = open(path_to_file, "w")
        f.write(json.dumps(self.test_results, indent=4))
        f.close()
        self.print_info("Results exported to JSON in '%s'" % path_to_file)

    def exportSQLITE(self, filename):
        basepath = os.path.dirname(filename)
        filename = os.path.basename(filename)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        # Exporting results
        # Connecting to sqlite
        conn = sqlite3.connect(path_to_file)
        # Creating a cursor object using the cursor() method
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS results(target VARCHAR(255), uuid VARCHAR(255), version VARCHAR(255), named_pipe VARCHAR(255), protocol_shortname VARCHAR(255), protocol_longname VARCHAR(512), function_name VARCHAR(255), result VARCHAR(255), path VARCHAR(512));")
        cursor.execute("DELETE FROM results;")
        for target in self.test_results.keys():
            for uuid in self.test_results[target].keys():
                for version in self.test_results[target][uuid].keys():
                    for function_name in self.test_results[target][uuid][version].keys():
                        for named_pipe in self.test_results[target][uuid][version][function_name].keys():
                            for test_result in self.test_results[target][uuid][version][function_name][named_pipe]:
                                cursor.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                                        target,
                                        uuid,
                                        version,
                                        named_pipe,
                                        test_result["protocol"]["shortname"],
                                        test_result["protocol"]["longname"],
                                        function_name,
                                        test_result["testresult"],
                                        str(bytes(test_result["exploitpath"], 'utf-8'))[2:-1].replace('\\\\', '\\')
                                    )
                                )
        # Commit your changes in the database
        conn.commit()
        # Closing the connection
        conn.close()
        self.print_info("Results exported to SQLITE3 db in '%s'" % path_to_file)
