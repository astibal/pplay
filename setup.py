import setuptools

with open("README.md", "r") as fh:

    long_description = fh.read()

setuptools.setup(
    name='pplay',
    version='1.7.3',
    scripts=['pplay.py'] ,
    author="Ales Stibal",
    author_email="astib@mag0.net",
    description="tool to replay and work with pcap and smcap (smithproxy capture) files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://bitbucket.org/astibal/pplay",
    packages=setuptools.find_packages(),

    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
        "Operating System :: OS Independent",
    ],
)