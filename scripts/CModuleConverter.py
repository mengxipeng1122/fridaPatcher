#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

# this class try to convert a c code to a typescript module
class CModuleConverter():
    def __init__(self):
        # always use ELF object file ?
        self.objfn = '/tmp/tt.o'
        self.templateFn=None
        self.source    = None
        self.secInfos = [] 
        self.secMap   = {} #  key -- section name, value -- section idx in secInfos; 
        self.symInfos = {} 
        self.relocInfos = []
        self.gotInfo    = None
        self.bs= None
        self.ks = None
        self.cs = None

    def compile(self, srcfn):
        raise Exception('please implement this function ' )

    def run(self, srcfn, tagfn):
        self.source = open(srcfn).read()
        self.compile(srcfn)
        binary = lief.parse(open(self.objfn,'rb'))
        self.updateSecInfos(binary)
        self.updateSymbolInfos(binary)
        self.updateRelocInfos(binary)
        # save bs for debug   
        self.outputTypescript(tagfn)

    def outputTypescript(self, fn):
        assert self.templateFn!=None, 'please provide  a valid template file name' 
        t = Template(open(self.templateFn).read())
        s = t.render(
            source      = self.source.splitlines(),
            secInfos    = self.secInfos      ,
            secMap      = self.secMap        ,
            symInfos    = self.symInfos      ,
            relocInfos  = self.relocInfos    ,
            gotInfo     = self.gotInfo       ,
            bs          = self.bs            ,
            hookInfo    = self.hookInfo      ,
            hexBsLenString =hex(len(self.bs)), 
        )
        open(fn,'w').write(s)
        
    def updateSecInfos(self,binary): # realloc self.bs too
        # write obj byte blocks
        offset = 0; bs=bytes()
        # write sections
        print('put sec' )
        secInfos = []
        secMap = {}
        for k, sec in enumerate(binary.sections):
            newSecInfo = {'offset':None} # offset is None means this section not be loaded
            secMap[sec.name] = k;
            offset=len(bs)
            if  sec.type == lief.ELF.SECTION_TYPES.PROGBITS \
             or sec.type == lief.ELF.SECTION_TYPES.NOBITS:
                content = bytes(sec.content) if sec.type == lief.ELF.SECTION_TYPES.PROGBITS else b'\0'*sec.size
                newSecInfo['offset']=offset
                bs+=content
                offset = len(bs); n_offset = getAlignNum(offset)
                if n_offset > offset: bs+= b'\0' *(n_offset-offset)
            secInfos.append(newSecInfo)
        print('allocate .got area for link external symbol link')
        offset = len(bs); n_offset = getAlignNum(offset)
        if n_offset > offset: bs+= b'\0' *(n_offset-offset)
        offset=len(bs)
        gotInfo = {'offset':offset, 'symbols':{}}
        gotSymOffset = 0;
        for k, symbol in enumerate(binary.symbols):
            if symbol.name ==  '': continue # skip empty name 
            if symbol.shndx != int(lief.ELF.SYMBOL_SECTION_INDEX.UNDEF): continue # only handle undef  symbols
            gotInfo['symbols'][symbol.name] = {'offset':gotSymOffset} # this offset is related to got area itself, not for bs
            bs+=b'\0'*4; gotSymOffset+=4;
        offset = len(bs); n_offset = getAlignNum(offset)
        if n_offset > offset: bs+= b'\0' *(n_offset-offset)
        self.bs = bytearray(bs)
        self.secInfos = secInfos;
        self.secMap   = secMap;
        self.gotInfo  = gotInfo

    def updateSymbolInfos(self, binary):
        print('get symbol' )
        symInfos = {} 
        for k, symbol in enumerate(binary.symbols):
            if symbol.name ==  '': continue # skip empty name 
            if symbol.shndx == int(lief.ELF.SYMBOL_SECTION_INDEX.UNDEF): continue # skip undef  symbols
            if symbol.shndx == int(lief.ELF.SYMBOL_SECTION_INDEX.ABS):   continue # skip abs  symbols
            if symbol.binding==    lief.ELF.SYMBOL_BINDINGS.LOCAL:       continue # skip local  symbols
            sec = self.secInfos[symbol.shndx]
            assert sec['offset'] != None, 'sec not load in when handle symbol' 
            offset = sec['offset']+symbol.value
            symInfos[symbol.name] = {'offset': offset};
        self.symInfos = symInfos

    def updateRelocInfos(self, binary):
        raise Exception('please implement this function ' )

    def generateTSModule(self):
        raise Exception('please implement this function ' )



