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
from jinja2 import Template

##################################################
# utils
def runCmd(cmd, showCmd =True, mustOk=False, showResult=False):
    '''
    run a shell command on PC and return the output result
    parameter:
        cmd --- the command line
        showCmd -- whether show running command
        mustOk -- if this option is True and command run failed, then raise a exception
        showResult -- show result of command
    '''
    if showCmd:
        print (cmd)
    ## run it ''
    result = ""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    ## But do not wait till netstat finish, start displaying output immediately ##
    while True:
        try:
            output = p.stdout.readline().decode()
        except UnicodeDecodeError as e:
            print(' UnicodeDecodeError ', e);
        if output == '' and p.poll() is not None:
            break
        if output:
            result+=str(output)
            if showResult:
                print(output.strip())
                sys.stdout.flush()
    stderr = p.communicate()[1]
    if stderr:
        print (f'STDERR:{stderr}')
    p_status = p.wait()
    if mustOk:
        if p_status is p_status !=0: raise Exception('run %s failed %d' %(cmd, p_status))
    return result

def getAlignNum(addr, align=0x10):
    addr1 = addr
    while(addr1 % align != 0): addr1+=1
    return addr1


# this class try to convert a c code to a typescript module
class CModuleConverter():
    def __init__(self):
        # always use ELF object file ?
        self.objfn = '/tmp/tt.o'
        self.secInfos = [] 
        self.secMap   = {} #  key -- section name, value -- section idx in secInfos; 
        self.symInfos = {} 
        self.relocInfos = []
        self.gotInfo    = None
        self.bs= None

    def compile(self, srcfn):
        raise Exception('please implement this function ' )

    def updateSecInfos(self,binary): # realloc self.bs too
        # write obj byte blocks
        offset = 0; bs=bytes()
        # write sections
        print('put sec' )
        secInfos = []
        secMap = {}
        for k, sec in enumerate(binary.sections):
            newSecInfo = {'sec':sec,'offset':None} # offset is None means this section not be loaded
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
            if symbol.shndx != int(lief.ELF.SYMBOL_SECTION_INDEX.UNDEF): continue # only handle undef  symbols
            gotInfo['symbols'][symbol.name] = gotSymOffset
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

    def initBytes(self):
        '''
            this function do the following tasks
            a. put all data need to load to a bytes variable 
            b. handle  all  independent relocs, 
            c. generates a symbol map, only can record offset now, because can not determine the start address now
        '''
        binary = lief.parse(open(self.objfn,'rb'))
        self.updateSecInfos(binary)
        self.updateSymbolInfos(binary)
        self.updateRelocInfos(binary)

    def generateTSModule(self):
        raise Exception('please implement this function ' )


class ThumbCModuleConverter(CModuleConverter):
    compiler='arm-linux-gnueabihf-gcc'
    compile_flag = ' -mlong-calls '

    def __init__(self):
        super().__init__()

    def compile(self, srcs):
        # only compile to a object file, never link
        if isinstance(srcs, list):
            # create a big cpp file for compile to object file 
            TEMP_SRC='/tmp/__final.cpp'
            with open(TEMP_SRC,'w') as f:
                for s in srcs: f.write(open(s).read())
            cmd = f'{ThumbCModuleConverter.compiler} -c -I. {ThumbCModuleConverter.compile_flag} -o  {self.objfn} -mthumb {TEMP_SRC}'
        elif isinstance(srcs, str):
            cmd = f'{ThumbCModuleConverter.compiler} -c -I. {ThumbCModuleConverter.compile_flag} -o  {self.objfn} -mthumb {srcs}'
        else:
            assert False, "srcs only can be of type list and str "
        print(runCmd(cmd, mustOk=True))

        relocInfos = []

    def updateRelocInfos(self, binary):
        print('handle relocs')
        relocInfos = []
        for k, reloc in enumerate(binary.relocations):
            newReloc = {'reloc':reloc, "handle":False}
            secIdx = self.secMap[reloc.section.name]
            sec    = self.secInfos[secIdx]
            symbolName  = reloc.symbol.name
            if sec['offset'] == None: continue # section not be loaded
            offset   = sec['offset'] + reloc.address
            typ         = int(reloc.type)
            if False: pass
            elif typ == 3: # R_ARM_REL32 # ((S + A) | T) | - P
                A = offset;
                P = struct.unpack('I',self.bs[offset:offset+4])[0]
                secIdx = reloc.info
                S = self.secInfos[secIdx]['offset']
                W = S+A-P
                self.bs[offset:offset+4] = struct.pack('I', W)
                newReloc['handle'] = True
            elif typ == 10: # R_ARM_THM_CAL # ((S + A) | T) - P
                if symbolName in self.symInfos:
                    newReloc['handle'] = True # do nothing
                else:
                    assert False, f' please handle reloc {reloc} {reloc.type}'
            elif typ == 25: #R_ARM_BASE_PREL: # B(S) + A - P
                assert symbolName in self.gotInfo['symbols'], f'can not find symbol {symbolName} in got'
                BS= self.gotInfo['offset'] + self.gotInfo['symbols'][symbolName]
                P = struct.unpack('I',self.bs[offset:offset+4])[0]
                A = offset;
                W = BS+A-P
                self.bs[offset:offset+4] = struct.pack('I', W)
                newReloc['handle'] = True
            elif typ == 26: # R_ARM_GOT_BREL # GOT(S) + A - GOT_ORG
                A = offset;
                assert symbolName in self.gotInfo['symbols'], f'can not found symbol {symbolName} in got '
                W = self.gotInfo['symbols'][symbolName]
                self.bs[offset:offset+4] = struct.pack('I', W)
                newReloc['handle'] = True
            else:
                assert False, f' please handle reloc {reloc} {reloc.type}'
            relocInfos.append(newReloc)
        self.relocInfos = relocInfos

    def generateTSModule(self):
        raise Exception('please implement this function ' )
    

def main():
    srcfn ='hook0.c'
    tagfn ='hook0.ts'
    # arm_compiler='/Users/mxp/work/armv8-rpi3-linux-gnueabihf/bin/armv8-rpi3-linux-gnueabihf-gcc'
    arm_compiler='arm-linux-gnueabihf-gcc'

    objfn = srcfn[:-2]+'.o'

    cmd = f'{arm_compiler} -mlong-calls -c -o  {objfn} -mthumb {srcfn}'
    print(cmd)
    runCmd(cmd,mustOk=True)

    objectRels =[]
    for k, reloc in enumerate(objbinary.relocations):
        secName = reloc.section.name
        offset      = secOffsectMap[secName]+reloc.address
        typ         = int(reloc.type)
        symbolName  = reloc.symbol.name
        print(reloc, reloc.section, typ, symbolName)
        objectRels.append({
            'offset': offset, 
            'type'  : typ,
            'symbolName'  : symbolName,
            })
    print(objectRels)

    jumpTargetOffset=len(bs);
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    CODE= """
                    PUSH \t {LR};
                    PUSH \t {R0-R7};
                    PUSH \t {R8-R12}; 
                    MRS  \t LR, CPSR;
                    PUSH \t {LR};
                """
    encoding, count = ks.asm(CODE)
    bs += bytes(encoding)
    curoffset  = len(bs)
    funoffset  = objectSymbolOffset['_fun']
    CODE= f'BL #{funoffset-curoffset-1}'
    encoding, count = ks.asm(CODE)
    bs += bytes(encoding)
    CODE = """
                    POP  \t {LR};
                    MSR  \t CPSR, LR;
                    POP  \t {R8-R12};
                    POP  \t {R0-R7};
                    POP  \t {LR};
                  """
    encoding, count = ks.asm(CODE)
    bs += bytes(encoding)
    originalCodeOffset = len(bs)
    bs+=b'\0'*8 # long jump need 8 bytes
    CODE = """
                    LDR PC, [PC, #0]
                  """
    encoding, count = ks.asm(CODE)
    bs += bytes(encoding)
    jumpBackOffset = len(bs)
    bs+=b'\0'*4 # jump back address
    offset = len(bs); n_offset = getAlignNum(offset)
    if n_offset > offset: bs+= b'\0' *(n_offset-offset)

    # write typescript source code with jinja2  engine
    t = Template(open('hook.arm32.thumb.jinjia').read())
    cCode = open(srcfn).read().splitlines()
    s = t.render( \
        bs=bs,  \
        cCode=cCode, \
        originalCodeOffset=originalCodeOffset, \
        jumpBackOffset=jumpBackOffset, \
        jumpTargetOffset=jumpTargetOffset, \
        objectSymbolOffset=objectSymbolOffset, \
        objectRels = objectRels, \
        )
    print(s)
    open(tagfn,'w').write(s)
    return 

def main():
    converter = ThumbCModuleConverter();
    converter.compile('fun0.cpp')
    converter.initBytes()


if __name__ == '__main__':
    main()

