import * as fridautils from './fridautils'
import * as path from 'path'
import * as hook0 from  './hook0'
const fs = require('frida-fs');

var test0 = ()=>{
    // list all export in lib
    Process.enumerateModules()
        .filter(m=>{
            return m.name.includes('frida');
        })
        .forEach(m=>{
            console.log(JSON.stringify(m));
            m.enumerateSymbols()
                .forEach(e=>{
                    console.log(JSON.stringify(e));
                })
            m.enumerateExports()
                .forEach(e=>{
                    console.log(JSON.stringify(e));
                })
        });

};

const soname = 'libnesec.so'
var test0 = ()=>{
    fridautils.hookDlopen(soname,()=>{
        console.log(soname, 'loaded');
        const m = Process.getModuleByName(soname);
        const fname = "JNI_OnLoad"
        const f = m.getExportByName(fname);
        Interceptor.attach(f,{
            onEnter:function(args){
                console.log(fname,'enter');
            },
            onLeave:(retval)=>{
                console.log(fname,'leave');
            },
        });
    });
};

//DexFile_openDexFileNative


var test0 = ()=>{
    const m = Process.getModuleByName("libart.so");
    let funOpenDexFile:NativePointer;
    m.enumerateSymbols()
        .filter(e=>{
            return e.name.includes("DexFile")
                && e.name.includes("openDexFile")
                ;
        })
        .forEach(e=>{
            console.log(JSON.stringify(e)); 
            funOpenDexFile = e.address;
        })
    let hooks:InvocationListener[]=[];
    let count=1;
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(rags)=>{
                console.log('enter load');
                // dump so 
                {
                    let m = Process.getModuleByName("libnesec.so");
                    let fn = '/mnt/sdcard/'+m.name +'.'+m.base+'.dump'
                    fridautils.dumpMemoryToFile(m.base,m.size, fn);
                }
                if(funOpenDexFile){
                    let hookOpenDexFile = Interceptor.attach(funOpenDexFile,{
                        onEnter:function(args){
                            let  s = Java.vm.getEnv().getStringUtfChars(args[2], null).readCString();
                            this.s = s;
                            console.log(s,'s');
                            let fn = "/mnt/sdcard/"+count+'.js'
                            fridautils.copyfile(s,fn)
                            fn+=1;
                            // let calls = Thread.backtrace(this.context, Backtracer.ACCURATE);
                            // calls.forEach(c=>{
                            //     console.log(JSON.stringify(c));
                            //     let m = Process.getRangeByAddress(c);
                            //     console.log(JSON.stringify(m));
                            // });
                        },
                        onLeave:function(retval){
                            console.log(this.s,'e');
                        }
                    });
                    hooks.push(hookOpenDexFile);
                }
                {
                    let open = Module.getExportByName(null,'__openat');
                    let h = Interceptor.attach(open, {
                        onEnter:function(args){
                            let s = args[1].readUtf8String()
                            console.log('open', s, args[1])
                        },
                        onLeave:function(retval){
                            console.log("open ok", retval)
                        },
                    })
                    hooks.push(h)
                }
                {
                    let write = Module.getExportByName(null, 'write');
                    let h = Interceptor.attach(write, {
                        onEnter:function(args){
                            console.log('write', args[0], args[1], args[2])
                        },
                        onLeave:function(retval){
                            console.log("write ok", retval)
                        },
                    })
                    hooks.push(h)
                }
            },
            onLeave:(retval)=>{
                console.log('leave load');
                hooks.forEach(h=>{ h.detach() })
            },
        }],
    ]));
}

var test0 = ()=>{
    let show=false;
    let hooks:InvocationListener[]=[];
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(rags)=>{
                console.log('enter load');
                show=true;
                Process.enumerateModules()
                    .filter(m=>{
                        return m.name.includes('ne')
                    })
                    .forEach(m=>{
                        console.log(JSON.stringify(m))
                    })
            },
            onLeave:(retval)=>{
                console.log('leave load');
                Process.enumerateModules()
                    .forEach(m=>{
                        console.log(JSON.stringify(m))
                    })
                fridautils.dumpSo('libnesec.so');
                fridautils.dumpSo('libneguard.so');
                show=false;
                hooks.forEach(h=>{ h.detach() })
            },
        }],
    ]));
}

var test0 = ()=>{
    let m = Process.getModuleByName('libnesec.so');
    let addr = m.base;
    do{
        let inst = Instruction.parse(addr);
        console.log(addr, inst.toString());
        addr=addr.add(inst.size);
    } while(addr.compare(m.base.add(m.size))<0);
}

var test0 = ()=>{
    let show=false;
    let hooks:InvocationListener[]=[];
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(rags)=>{
                console.log('enter load');
                show=true;
                Process.enumerateModules()
                    .filter(m=>{
                        return m.name.includes('ne')
                    })
                    .forEach(m=>{
                        console.log(JSON.stringify(m))
                    })
            },
            onLeave:(retval)=>{
                console.log('leave load');
                Process.enumerateModules()
                    .forEach(m=>{
                        console.log(JSON.stringify(m))
                    })
                //fridautils.dumpSo('libnesec.so');
                fridautils.findInstructInso('svc', 'libnesec.so');
                fridautils.findInstructInso('svc', 'libneguard.so');
                fridautils.findInstructInso('svc', 'libc.so');
                show=false;
                hooks.forEach(h=>{ h.detach() })
            },
        }],
    ]));
}


var test0 = ()=>{
    let m = Process.getModuleByName('libc.so');
    let ex = m.getExportByName('read');
    let sz = 0x100;
    let addr = ex;
    do{
        let inst = Instruction.parse(addr);
        console.log(addr, inst.toString());
        addr=addr.add(inst.size);
    } while(addr.compare(ex.add(sz))<0);
}

var test0 = ()=>{
    let show=false;
    let hooks:InvocationListener[] = [];
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(rags)=>{
                console.log('enter load');
                show=true;
                let offs = [
                    {soname:"libnesec.so",  loc:0x0b3288,},
                    {soname:"libnesec.so",  loc:0x137984,},
                    //{soname:"libneguard.so",loc:0x512984,},
                    //{soname:null,loc:"dlopen",},
                ];
                fridautils.hookFunList(offs, hooks);
                fridautils.hookDlopen('libneguard.so',()=>{
                    let offs = [
                        {soname:"libneguard.so",loc:0x512984,},
                    ];
                    fridautils.hookFunList(offs, hooks);

                });
            },
            onLeave:(retval)=>{
                console.log('leave load');
                show=false;
                fridautils.dumpSo('libc.so');
                hooks.forEach(h=>{ h.detach() })
            },
        }],
    ]));
}

var test0 = ()=>{
    let show=false;
    let hooks:InvocationListener[] = [];
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(args)=>{
                console.log('enter load');
                show=true;
                console.log(
                        args[0],
                        args[1],
                        args[2],
                        args[3],
                        args[4],
                        args[5],
                        args[6],
                        )
//                fridautils.dumpProgress('/mnt/sdcard/dumps')
            },
            onLeave:(retval)=>{
                console.log('leave load');
                show=false;
                hooks.forEach(h=>{ h.detach() })
            },
        }],
    ]));
}

var test0 = ()=>{
    let show=false;
    let hooks:InvocationListener[] = [];
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(args)=>{
                console.log('enter load');
                show=true;
            },
            onLeave:(retval)=>{
                console.log('leave load');
                show=false;
                hooks.forEach(h=>{ h.detach() })
            },
        }],
    ]));
}

var test0 = ()=>{
    let show=false;
    let dumped = false;
    let hooks:InvocationListener[] = [];
    // find open memory function
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(args)=>{
                console.log('enter load');
                let infos:fridautils.HookFunInfo[] = [
// art::ClassLinker::OpenDexFilesFromOat(char const*, char const*, std::__1::vector<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::allocator<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >*)"
{enable:false,soname:"libart.so", loc:"_ZN3art11ClassLinker19OpenDexFilesFromOatEPKcS2_PNSt3__16vectorINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS8_ISA_EEEE", enterFun:function(args:NativePointer[], tstr:string, thiz:object, userdata: any ){
    let s1 = args[1].readUtf8String();
    let s2 = args[2].readUtf8String();
    console.log(tstr, s1, s2);
}, },
//art::OS::OpenFileWithFlags(char const*, int)
{enable:false,soname:"libart.so", loc:"_ZN3art2OS17OpenFileWithFlagsEPKci"                                                                                                       , enterFun:function(args:NativePointer[], tstr:string, thiz:object, userdata: any ){ 
    let s1 = args[0].readUtf8String();
}, },
//art::DexFile::OpenMemory(unsigned char const*, unsigned int, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, unsigned int, art::MemMap*, art::OatDexFile const*, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >*)
{soname:"libart.so", loc:"_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_"    , enterFun:function(args:NativePointer[], tstr:string, thiz:object, userdata: any ){   
    let p = args[1];
    let n = args[2].toUInt32();
    let pthis = thiz as InvocationContext;
    console.log(tstr, p, n, pthis.returnAddress);
    //fridautils.dumpMemory(p);
    //fridautils.showBacktrace(pthis, tstr);
}, },
{enable:false,soname:"libart.so", loc:"_ZN3art7DexFile8OpenFileEiPKcbPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE"                                             },
{enable:false,soname:"libart.so", loc:"_ZN3art7OatFile4OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_PhSA_bPKcPS7_"                                     },
{enable:false,soname:"libart.so", loc:"_ZN9unix_file6FdFile4OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEit"                                              },
{enable:false,soname:"libart.so", loc:"_ZNK3art10OatDexFile11OpenDexFileEPNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE"                                         },
{soname:"libnesec.so", loc:ptr(0xa1114219).sub(0xa10af000).toUInt32()   , enterFun:function(args:NativePointer[], tstr:string, thiz:object, userdata: any ){  
    let pthis = thiz as InvocationContext;
    if(!dumped){
        fridautils.dumpProgress(pthis,"/mnt/sdcard/dumps/");
        dumped=true;
    }
}, },
                ]
                show=true;
                fridautils.hookFunList(infos, hooks);
            },
            onLeave:(retval)=>{
                console.log('leave load');
                show=false;
                hooks.forEach(h=>{ h.detach() })
            },
        }],
    ]));
}


console.log('hello world')
test0()
