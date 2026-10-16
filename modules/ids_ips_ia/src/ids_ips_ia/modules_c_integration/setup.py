#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Oct 14 00:00:44 2026

@author: hounsousamuel
"""

"""
Compiler la liaison :   cd python && python3 setup.py build_ext --inplace
Le .so produit s'importe avec  import ids_engine  (depuis le dossier python/ ou en l'ajoutant au PYTHONPATH). 
"""

import os
import numpy as np
from Cython.Build import cythonize
from setuptools import Extension, setup

DIR = os.path.abspath(os.path.dirname(__file__))

C = os.path.abspath(os.path.join(DIR, "..", "modules_c"))

C_DIR_FILES = [
    ('engine', 'engine.c'),
    ('ipset', 'ipset.c'),
    ('ipset_m', 'ipset_m.c'),
    ('mmap_ring', 'mmap_ring.c'),
    ('capture', 'capture.c'),
    ('capture', 'bpf_filter.c'),
    ('parser', 'parser.c'),
    ('flows', 'flow.c'),
    ('flows', 'flow_table.c'),
    ('dict', 'dict.c'),
    ('dchained_list', 'dchained_list.c'),
    ('portmap', 'portmap.c'),
    ('utils', 'utils.c'),
    ('rules', 'rules.c')
]

SOURCES = ["core_c.pyx"] + [os.path.abspath(os.path.join(C, *f)) for f in C_DIR_FILES]

setup(
    name="ids_ips_core_c",
    ext_modules=cythonize(
        [
            Extension(
                "ids_ips_core_c", 
                SOURCES,
                extra_compile_args=["-std=gnu11", "-O2", "-Wall", "-march=x86-64-v2"],
                libraries=["pthread", "rt", "pcap"],
                include_dirs=[np.get_include()],
           )
        ],
        compiler_directives={"language_level": 3},
    ),
)
