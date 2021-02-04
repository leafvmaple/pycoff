from setuptools import setup
from os import path

with open('README.rst') as f:
    long_description = f.read()

setup(
    name="pycoff",
    version="0.1.0",
    keywords=["coff", "elf", "pe", "pycoff"],
    description="Coff(ELF on Linux, PE on Windows) parser",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="BSD License",
    url="https://github.com/leafvmaple/pycoff",
    author="Zohar Lee",
    author_email="leafvmaple@gmail.com",
    packages=find_packages(),
    include_package_data=True,
    platforms="any",
    classifiers={
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
    },
    # install_requires = ["codecs"]
)