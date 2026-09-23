import setuptools
from os import path
this_directory = path.abspath(path.dirname(__file__))

with open(path.join(this_directory, 'README.md'), encoding='utf-8') as fh:

    long_description = fh.read()

setuptools.setup(
    name='pplay',
    version='2.0.11',
    scripts=['pplay.py', 'smcap2pcap'],
    author="Ales Stibal",
    author_email="astib@mag0.net",
    license="LGPL-2.0-or-later",
    description="tool to replay and work with pcap and smcap (smithproxy capture) files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/astibal/pplay",
    packages=setuptools.find_packages(),

    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    install_requires=["scapy", "colorama", "paramiko", "requests", "pysocks", "cryptography"]
)
