import setuptools
from pkg_resources import DistributionNotFound, get_distribution

from tinytuya import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

INSTALL_REQUIRES = [
    'requests',      # Used for Setup Wizard - Tuya IoT Platform calls
    'colorama',      # Makes ANSI escape character sequences work under MS Windows.
    #'netifaces',     # Used for device discovery, mainly required on multi-interface machines
]

CHOOSE_CRYPTO_LIB = [
    'cryptography',  # pyca/cryptography - https://cryptography.io/en/latest/
    'pycryptodome',  # PyCryptodome      - https://pycryptodome.readthedocs.io/en/latest/
    'pyaes',         # pyaes             - https://github.com/ricmoo/pyaes
    'pycrypto',      # PyCrypto          - https://www.pycrypto.org/
]

pref_lib = CHOOSE_CRYPTO_LIB[0]
for cryptolib in CHOOSE_CRYPTO_LIB:
    try:
        get_distribution(cryptolib)
        pref_lib = cryptolib
        break
    except DistributionNotFound:
        pass

INSTALL_REQUIRES.append( pref_lib )

setuptools.setup(
    name="tinytuya",
    version=__version__,
    author="Jason Cox",
    author_email="jason@jasonacox.com",
    description="Python module to interface with Tuya WiFi smart devices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/jasonacox/tinytuya',
    packages=setuptools.find_packages(exclude=("sandbox",)),
    install_requires=INSTALL_REQUIRES,
    entry_points={"console_scripts": ["tinytuya=tinytuya.__main__:dummy"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
