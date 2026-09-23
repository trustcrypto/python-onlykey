from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='onlykey',
    version='1.3.0',
    description='OnlyKey client and command-line tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/trustcrypto/python-onlykey',
    author='CryptoTrust',
    author_email='admin@crp.to',
    license='MIT',
    # The age plugin uses PEP 604 unions (`Stanza | None`) and PEP 585 generics
    # (`list[str]`, `tuple[bytes, bytes]`) at module scope, which are syntax
    # errors at import time on 3.9. Declare the floor so pip refuses to install
    # an interpreter where `age-plugin-onlykey` cannot start.
    python_requires='>=3.10',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    # openpgp_bridge holds only .js (no __init__.py), so find_packages() does
    # not see it and setuptools warns that the data will be dropped by a future
    # release. Naming it as a package keeps bridge.js and openpgp.js in the wheel
    # at the path pgp_bridge.py loads them from.
    packages=find_packages(exclude=['contrib', 'docs', 'tests']) + ['onlykey.openpgp_bridge'],
    package_data={'onlykey.openpgp_bridge': ['*.js']},
    include_package_data=True,
    entry_points = {
        'console_scripts': [
            'onlykey-cli=onlykey.cli:main',
            'age-plugin-onlykey=onlykey.age_plugin.cli:main',
        ],
    },
    install_requires=['hidapi', 'aenum', 'six', 'prompt_toolkit>=2', 'pynacl>=1.4.0', 'ecdsa>=0.13', 'Cython>=0.23.4', 'onlykey-solo-python>=0.0.31'],
    extras_require={
        'age': ['cryptography>=41.0', 'kyber-py>=1.0'],
    },
)
