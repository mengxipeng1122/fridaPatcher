#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this python script try to compile c source code to a object file and output for using of frida
# only support 32bit, ARM/thumb so far
import sys
import struct
import os
import subprocess
import lief
from hexdump import *
from keystone import *
from capstone import *
from jinja2 import Template

from utils import *
from ThumbCModuleConverter import *
from ArmCModuleConverter import *

def main():
    converter = ThumbCModuleConverter();
    converter.run('hook0.cpp', 'hook0.ts')
    # write for debug 
    open('/tmp/ff.bin','wb').write(converter.bs)


if __name__ == '__main__':
    main()

