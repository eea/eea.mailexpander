#!/bin/sh

rm -rf bin/ lib/ lib64/ local/ include/ build/ dist/ htmlcov/

VENV=virtualenv-1.11.4/virtualenv.py
URL="https://pypi.python.org/packages/source/v/virtualenv/virtualenv-1.11.4.tar.gz#md5=9accc2d3f0ec1da479ce2c3d1fdff06e"

curl $URL > /tmp/virtualenv.tgz
tar xzf /tmp/virtualenv.tgz -C ./
/usr/bin/python2.7 $VENV --clear --system-site-packages ./

bin/pip install -e .
bin/pip install eea.mailexpander[testing]

rm -rf ./virtualenv*
