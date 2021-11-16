"""
Adapted from https://github.com/pybind/cmake_example/blob/master/setup.py.
"""

import pathlib
import subprocess
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext


class CMakeExtension(Extension):
    def __init__(self, name: str, source_dir: str = ""):
        Extension.__init__(self, name, sources=[])
        self.source_dir = pathlib.Path(source_dir).resolve()


class CMakeBuild(build_ext):
    def build_extension(self, extension: CMakeExtension):
        extension_root_dir = pathlib.Path(
            self.get_ext_fullpath(extension.name)
        ).parent.resolve()

        build_dir = pathlib.Path(self.build_temp).resolve()
        if not build_dir.exists():
            build_dir.mkdir(parents=True)

        # Generate build files.
        config = "Debug" if self.debug else "Release"
        subprocess.check_call(
            [
                "cmake",
                extension.source_dir,
                f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extension_root_dir}",
                f"-DPYTHON_EXECUTABLE={sys.executable}",
                f"-DCMAKE_BUILD_TYPE={config}",
                f"-DBLACKSMITH_ENABLE_PYBIND=ON",
            ],
            cwd=build_dir,
        )

        # Build library.
        subprocess.check_call(["cmake", "--build", "."], cwd=build_dir)


setup(
    name="blacksmith_native",
    version="0.0.1",
    ext_modules=[CMakeExtension("blacksmith_native")],
    cmdclass={"build_ext": CMakeBuild},
    zip_safe=False,
    python_requires=">=3.6",
)
