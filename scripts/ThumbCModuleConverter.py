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
from CModuleConverter import *

class ThumbCModuleConverter(CModuleConverter):

    def __init__(self):
        super().__init__()
        self.compiler='arm-linux-gnueabihf-gcc'
        self.compile_flag = ' -mlong-calls '
        moudle_path = os.path.dirname(os.path.abspath(__file__))
        self.templateFn = os.path.join(moudle_path, 'fun.thumb.jinjia')
        self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        hookCODE= '''
                    PUSH \t {LR};                                            @0x0: 
                    PUSH \t {R0-R7};                                         @0x2: 
                    PUSH \t {R8-R12};                                        @0x4: 
                    MRS  \t LR, CPSR;                                        @0x8: 
                    PUSH \t {LR};                                            @0xc: 
                    ADD  \t R4,  PC, #0x40                                   @0xe: 
                    LDR  \t R4, [R4]                                         @0x12:
                    BLX  \t R4; @ call fun                                   @0x14:
                    POP  \t {LR};                                            @0x16:
                    MSR  \t CPSR, LR;                                        @0x1a:
                    POP  \t {R8-R12};                                        @0x1e:
                    POP  \t {R0-R7};                                         @0x22:
                    POP  \t {LR};                                            @0x24:
                    NOP  \t ;  @ write origin code                           @0x28:
                    NOP  \t ;                                                @0x2a:
                    NOP  \t ;                                                @0x2c:
                    NOP  \t ;                                                @0x2e:
                    LDR  \t PC, [PC, #-0x00]                                 @0x30:
                    NOP  \t ;  @ write jump back address                     @0x34:
                    NOP  \t ;                                                @0x38:
                    NOP  \t ;                                                @0x3a:
                    NOP  \t ;                                                @0x3e:
                    NOP  \t ;  @ write call fun address                      @0x40:
                    NOP  \t ;                                                @0x42:
                    NOP  \t ;                                                @0x3c:
                    NOP  \t ;                                                @0x3e:
            '''
        encoding, count = self.ks.asm(hookCODE);
        # 
        hookINST =bytes(encoding);
        open('/tmp/bb.bin','wb').write(hookINST); # save for debug 
        for (address, size, mnemonic, op_str) in self.md.disasm_lite(hookINST, 0):
	        print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
        longJumpCODE = '''
                    LDR  \t PC, [PC, #0x0];                                  @0x0:	
                    NOP  \t;                                                 @0x4
                    NOP  \t;                                                 @0x6
            '''
        encoding, count = self.ks.asm(longJumpCODE)
        longJumpINST =bytes(encoding);
        self.hookInfo={
                'INST':              hookINST,
                'funOffset'         :0x40,
                'originCodeOffset'  :0x28,
                'backAddressOffset' :0x34,
                'longJumpINST'      :longJumpINST,
                'longJumpOffset'    :0x04,
                };


    def compile(self, srcfn):
        # only compile to a object file, never link
        cmd = f'{self.compiler} -c -I. {self.compile_flag} -o  {self.objfn} -mthumb {srcfn}'
        print(runCmd(cmd, mustOk=True))

    def updateRelocInfos(self, binary):
        print('handle relocs')
        bs = bytearray(self.bs) # need to change bs
        relocInfos = []
        for k, reloc in enumerate(binary.relocations):
            newReloc = {"handle":False}
            secIdx = self.secMap[reloc.section.name]
            sec    = self.secInfos[secIdx]
            symbolName  = reloc.symbol.name
            if sec['offset'] == None: continue # section not be loaded
            offset   = sec['offset'] + reloc.address
            typ         = int(reloc.type)
            if False: pass
            elif typ == 3: # R_ARM_REL32 # ((S + A) | T) | - P
                A = offset;
                P = struct.unpack('I',bs[offset:offset+4])[0]
                secIdx = reloc.info
                S = self.secInfos[secIdx]['offset']
                W = S-A+P
                bs[offset:offset+4] = struct.pack('I', W)
                newReloc['handle'] = True
            elif typ == 10: # R_ARM_THM_CAL # ((S + A) | T) - P
                assert symbolName in self.symInfos, f'can not found symbol {symbolName} '
                # insert a BL code 
                symbolOffset = self.symInfos[symbolName]['offset']
                encoding, count = self.ks.asm(f'BL #{hex(symbolOffset)}', offset)
                bs[offset:offset+4]=bytes(encoding)
                newReloc['handle'] = True # do nothing
            elif typ == 25: #R_ARM_BASE_PREL: # B(S) + A - P
                assert symbolName in self.gotInfo['symbols'], f'can not find symbol {symbolName} in got'
                BS= self.gotInfo['offset'] + self.gotInfo['symbols'][symbolName]['offset']
                P = struct.unpack('I',bs[offset:offset+4])[0]
                A = offset;
                W = BS-A+P
                bs[offset:offset+4] = struct.pack('I', W)
                newReloc['handle'] = True
            elif typ == 26: # R_ARM_GOT_BREL # GOT(S) + A - GOT_ORG
                A = offset;
                assert symbolName in self.gotInfo['symbols'], f'can not found symbol {symbolName} in got '
                W = self.gotInfo['symbols'][symbolName]['offset']
                bs[offset:offset+4] = struct.pack('I', W)
                newReloc['handle'] = True
            else:
                assert False, f' please handle reloc {reloc} {reloc.type}'
            relocInfos.append(newReloc)
        self.bs = bs; # write back 
        self.relocInfos = relocInfos

    def generateTSModule(self):
        raise Exception('please implement this function ' )
    

