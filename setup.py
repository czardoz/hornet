# Need to import multiprocessing to work around a
# bug (http://bugs.python.org/issue15881#msg170215)

import multiprocessing
from setuptools import setup

setup(
    name='hornet',
    version='0.0.1',
    description='SSH Honeypot',
    url='https://github.com/czardoz/hornet',
    author='Aniket Panse',
    author_email='aniketpanse@gmail.com',
    license='GPLv3',
    packages=['hornet'],
    zip_safe=False,
    install_requires=open('requirements.txt').readlines(),
    test_suite='nose.collector',
    long_description=open('README.rst').read(),
    tests_require=['nose'],
    scripts=['bin/hornet'],
    dependency_links=['git+https://github.com/ianepperson/telnetsrvlib.git#egg=telnetsrv-0.4.1']
)
