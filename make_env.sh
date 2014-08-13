#!/bin/sh

VENV=virtualenv-1.11.4/virtualenv.py
URL="https://pypi.python.org/packages/source/v/virtualenv/virtualenv-1.11.4.tar.gz#md5=9accc2d3f0ec1da479ce2c3d1fdff06e"

curl $URL > /tmp/virtualenv.tgz
tar xzf /tmp/virtualenv.tgz -C ./
/usr/bin/python2.7 $VENV ./

bin/pip install pytest
bin/pip install Mock
bin/pip install python-ldap

rm -rf ./virtualenv*
