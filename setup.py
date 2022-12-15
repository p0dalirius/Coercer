#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : setup.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Jul 2022

import setuptools

long_description = """
# Coercer

<p align="center">
  A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through 9 methods.
  <br>
  <img alt="PyPI" src="https://img.shields.io/pypi/v/coercer">
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/Coercer">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
</p>


## Features

 - Core:
    + [x] Lists open SMB pipes on the remote machine (in modes [scan](./documentation/Scan-mode.md) authenticated and [fuzz](./documentation/Fuzz-mode.md) authenticated)
    + [x] Tries to connect on a list of known SMB pipes on the remote machine (in modes [scan](./documentation/Scan-mode.md) unauthenticated and [fuzz](./documentation/Fuzz-mode.md) unauthenticated)
    + [x] Calls one by one all the vulnerable RPC functions to coerce the server to authenticate on an arbitrary machine.
    + [x] Random UNC paths generation to avoid caching failed attempts (all modes)
    + [x] Configurable delay between attempts with `--delay`
 - Options:
    + [x] Filter by method name with `--filter-method-name`, by protocol name with `--filter-protocol-name` or by pipe name with `--filter-pipe-name`(all modes) 
    + [x] Target a single machine `--target` or a list of targets from a file with `--targets-file`
    + [x] Specify IP address OR interface to listen on for incoming authentications. (modes [scan](./documentation/Scan-mode.md) and [fuzz](./documentation/Fuzz-mode.md))
 - Exporting results
    + [x] Export results in SQLite format (modes [scan](./documentation/Scan-mode.md) and [fuzz](./documentation/Fuzz-mode.md))
    + [x] Export results in JSON format (modes [scan](./documentation/Scan-mode.md) and [fuzz](./documentation/Fuzz-mode.md))
    + [x] Export results in XSLX format (modes [scan](./documentation/Scan-mode.md) and [fuzz](./documentation/Fuzz-mode.md))

## Installation

You can now install it from pypi (latest version is <img alt="PyPI" src="https://img.shields.io/pypi/v/coercer">) with this command:

```
sudo python3 -m pip install coercer
```

## Quick start

 - You want to **assess** the Remote Procedure Calls listening on a machine to see if they can be leveraged to coerce an authentication?
   + Use [**scan** mode](./documentation/Scan-mode.md), example:

    https://user-images.githubusercontent.com/79218792/204374471-bc5094a3-8539-4df7-842e-faadcaf9c945.mp4

 - You want to **exploit** the Remote Procedure Calls on a remote machine to coerce an authentication to ntlmrelay or responder?
   + Use [**coerce** mode](./documentation/Coerce-mode.md), example:

    https://user-images.githubusercontent.com/79218792/204372851-4ba461ed-6812-4057-829d-0af6a06b0ecc.mp4
   
 - You are doing **research** and want to fuzz Remote Procedure Calls listening on a machine with various paths?
   + Use [**fuzz** mode](./documentation/Fuzz-mode.md), example:

    https://user-images.githubusercontent.com/79218792/204373310-64f90835-b544-4760-b0a3-3071429b3940.mp4

---

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits

 - [@tifkin_](https://twitter.com/tifkin_) and [@elad_shamir](https://twitter.com/elad_shamir) for finding and implementing **PrinterBug** on [MS-RPRN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)
 - [@topotam77](https://twitter.com/topotam77) for finding and implementing **PetitPotam** on [MS-EFSR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
 - [@topotam77](https://twitter.com/topotam77) for finding and [@_nwodtuhs](https://twitter.com/_nwodtuhs) for implementing **ShadowCoerce** on [MS-FSRVP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
 - [@filip_dragovic](https://twitter.com/filip_dragovic) for finding and implementing **DFSCoerce** on [MS-DFSNM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)
"""

with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [x.strip() for x in f.readlines()]

setuptools.setup(
    name="coercer",
    version="2.4",
    description="",
    url="https://github.com/p0dalirius/Coercer",
    author="Podalirius",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="podalirius@protonmail.com",
    packages=["coercer", "coercer.core", "coercer.methods", "coercer.models", "coercer.network"],
    package_data={'coercer': ['coercer/methods/']},
    include_package_data=True,
    license="GPL2",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    entry_points={
        'console_scripts': ['Coercer=coercer.__main__:main']
    }
)
