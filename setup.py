#!/usr/bin/env python

from setuptools import setup
from pyxolotl.version import __version__

setup(
    name="Pyxolotl",
    version=__version__,
    description="Send and receive messages encrypted with Axolotl (Double Ratchet) protocol",
    author="Michal Krenek (Mikos)",
    author_email="m.krenek@gmail.com",
    url="https://github.com/xmikos/pyxolotl",
    license="GNU GPLv3",
    packages=["pyxolotl"],
    entry_points={
        "console_scripts": [
            "pyxolotl=pyxolotl.__main__:main"
        ],
    },
    install_requires=[
        "python-axolotl",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography"
    ]
)
