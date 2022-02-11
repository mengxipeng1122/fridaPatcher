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

class ArmCModuleConverter(CModuleConverter):
    def __init__(self):
        super().__init__()
        self.compiler='arm-linux-gnueabihf-gcc'
        self.compile_flag = ' -mlong-calls '
        moudle_path = os.path.dirname(os.path.abspath(__file__))
        self.templateFn = os.path.join(moudle_path, 'fun.arm32.jinjia')
        self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        hookCODE= '''
                    PUSH \t {LR};                                            @0x0:	
                    PUSH \t {R0-R7};                                         @0x4:	
                    PUSH \t {R8-R12};                                        @0x8:	
                    MRS  \t LR, CPSR;                                        @0xc:	
                    PUSH \t {LR};                                            @0x10:	
                    LDR  \t R4, [PC, #4]                                     @0x14:	
                    ADD  \t PC, #8                                           @0x18:	
                    NOP  \t ;   @ write  call fun address in here in here    @0x1c:	
                    NOP  \t ;                                                @0x20:	
                    NOP  \t ;                                                @0x24:	
                    BLX  \t R4; @ call fun                                   @0x28:	
                    NOP  \t ;                                                @0x2c:	
                    POP  \t {LR};                                            @0x30:	
                    MSR  \t CPSR, LR;                                        @0x34:	
                    POP  \t {R8-R12};                                        @0x38:	
                    POP  \t {R0-R7};                                         @0x3c:	
                    POP  \t {LR};                                            @0x40:	
                    NOP  \t ;  @ write  origin code in here                  @0x44:	
                    NOP  \t ;                                                @0x48:	
                    NOP  \t ;                                                @0x4c:	
                    NOP  \t ;                                                @0x50:	
                    NOP  \t ;                                                @0x54:	
                    NOP  \t ;                                                @0x58:	
                    LDR  \t PC, [PC, #0]                                     @0x5c:	
                    NOP  \t ;  @ write jmpback address in here               @0x60:	
                    NOP  \t ;                                                @0x64:	
                    NOP  \t ;                                                @0x68:	
                    NOP  \t ;                                                @0x6c:	
        '''
        encoding, count = self.ks.asm(hookCODE);
        # 
        for (address, size, mnemonic, op_str) in self.md.disasm_lite(bytes(encoding), 0):
	        print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
        self.hookInfo={
                'INST': bytes(encoding),
                'funOffset'         :0x1c,
                'originCodeOffset'  :0x44,
                'backAddressOffset' :0x60,
                };

    def compile(self, srcfn):
        # only compile to a object file, never link
        cmd = f'{self.compiler} -c -I. {self.compile_flag} -o  {self.objfn} -marm {srcfn}'
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
            elif typ == 28: # R_ARM_CALL #
                assert symbolName in self.symInfos, f'can not found symbol {symbolName} '
                # insert a BL code 
                symbolOffset = self.symInfos[symbolName]['offset']
                encoding, count = self.ks.asm(f'BL #{hex(symbolOffset)}', offset)
                bs[offset:offset+4]=bytes(encoding)
                newReloc['handle'] = True # do nothing
            else:
                assert False, f' please handle reloc {reloc} {reloc.type}'
            relocInfos.append(newReloc)
        self.bs = bs; # write back 
        self.relocInfos = relocInfos

    def generateTSModule(self):
        raise Exception('please implement this function ' )


