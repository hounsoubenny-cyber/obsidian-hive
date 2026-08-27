#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 15:29:03 2026

@author: hounsousamuel

Compilation du module Cython Anomaly Scorer.
Exécution : python setup.py build_ext --inplace

"""

from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy as np

# =============================================================================
# EXTENSION CYTHON
# =============================================================================

extensions = [
    Extension(
        name="calculate_ip_score_anomaly_cython",
        sources=["calculate_ip_score_anomaly_cython.pyx"],
        include_dirs=[np.get_include()],
        extra_compile_args=["-O3", "-march=native", "-ffast-math"],
        language="c",
    ),
]

# =============================================================================
# COMPILATION
# =============================================================================

setup(
    name="AnomalyScorerCython",
    version="1.0.0",
    description="Module Cython optimisé pour AnomalyScorer",
    author="hounsousamuel",
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            'boundscheck': False,
            'wraparound': False,
            'initializedcheck': False,
            'cdivision': True,
            'language_level': "3",
        },
    ),
    zip_safe=False,
)