import setuptools
from os import path
this_directory = path.abspath(path.dirname(__file__))

with open(path.join(this_directory, 'README.rst')) as fh:

    long_description = fh.read()

setuptools.setup(
    name='pplay',
    version='2.0.5post4',
    scripts=['pplay.py', 'smcap2pcap'],
    author="Ales Stibal",
    author_email="astib@mag0.net",
    description="tool to replay and work with pcap and smcap (smithproxy capture) files",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/astibal/pplay",
    packages=setuptools.find_packages(),

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    install_requires=["scapy", "colorama", "paramiko", "requests", "pysocks", "cryptography"]
)
