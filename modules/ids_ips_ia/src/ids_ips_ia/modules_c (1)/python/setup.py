"""Compiler la liaison :   cd python && python3 setup.py build_ext --inplace
Le .so produit s'importe avec  import ids_engine  (depuis le dossier python/ ou en l'ajoutant au PYTHONPATH). """
from setuptools import Extension, setup
from Cython.Build import cythonize

C = "../"
SOURCES = ["ids_engine.pyx"] + [C + f for f in [
    "engine/engine.c", "ipset/ipset.c", "mmap_ring/mmap_ring.c", "capture/capture.c",
    "parser/parser.c", "flows/flow.c", "flows/flow_table.c", "dict/dict.c",
    "dchained_list/dchained_list.c", "portmap/portmap.c", "utils/utils.c", "rules/rules.c",
]]

setup(
    name="ids_engine",
    ext_modules=cythonize(
        [Extension("ids_engine", SOURCES, extra_compile_args=["-std=gnu11", "-O2", "-Wall"],
                   libraries=["pthread", "rt"])],
        compiler_directives={"language_level": 3},
    ),
)
