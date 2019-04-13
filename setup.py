# -*- coding: utf-8 -*-

import sys
from setuptools import setup, find_packages

from Cython.Build import cythonize


if sys.version_info < (3, 5,):
    raise RuntimeError("aioclient requires Python 3.5.0+")


setup(
    name='aioclient',
    version='0.0.1',
    install_requires=[
        "cython",
    ],
    url='https://github.com/phlax/aioclient',
    license='GPL3',
    author='Ryan Northey',
    author_email='ryan@synca.io',
    packages=find_packages(),
    include_package_data=True,
    description='An obedient worker',
    long_description='Runs tasks async',
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: GPL3 License',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={'console_scripts': [
        'aioclient = aioclient.cli:cli',
    ]},
    ext_modules=(
        cythonize("aioclient/*.pyx", annotate=True)))
