// import { log } from "./logger";


import * as fridautils from './fridautils'
import * as hook from './hook0'
import * as path from 'path'
import { log } from 'console';
// import * as fs  from 'frida-fs'
const fs = require('frida-fs');

var soname = 'libnesec.so'

var test0 = function() {
    console.log(hook.code.buffer)

}

const myputs = new NativeCallback(function(s){
        const ss = s.readUtf8String();
        console.log(ss);
    }, 'void',['pointer']);

var test0 = function(){
    let dlopen = Module.getExportByName(null, 'dlopen');
    console.log(dlopen)
    var attached = false;
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            if(!attached) {
            const loadpath = args[0].readUtf8String();
            this.loadpath = loadpath;
            }
        },
        onLeave: function (retval) {
            if(!attached) {
                if ( retval.toUInt32() != 0) {
                    if (path.basename(this.loadpath) == soname){
                        console.log(this.loadpath, 'loaded')
                        let m = Process.getModuleByName(soname);
                        console.log('myputs', JSON.stringify(myputs))
                        const newCode = hook.code.link(m.base.add(0x68818), new Map<string, NativePointer>([
                            ["myputs", myputs],
                            ]), true);
                        {
                            // alloc memory 
                            //const newBuffer  = Memory.alloc(Process.pageSize,{near:m.base,maxDistance:0x2000000})
                            //console.log('newBuffer', newBuffer)
                        }
                        {
                            let p = newCode
                            let n = 0x100;
                            console.log('p',p);
                            console.log(hexdump(p.readByteArray(n) as ArrayBuffer, {ansi:true}));
                        }
                        {
                            let p = m.base.add(0x68810)
                            let n = 0x40
                            console.log('p',p);
                            console.log(hexdump(p.readByteArray(n) as ArrayBuffer, {ansi:true}));
                        
                        }
                        attached=true;
                    }
                }
            }
        },
    });
}

var test0 = function(){
    fridautils.hookDlopen(soname,function(){
        var show = false;
        let funs= [
// {enable:true, loc:'JNI_OnLoad', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:object, userdata:any){}, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },
            {enable:false, loc:0x6a511, nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
                let m = Process.getModuleByName(soname);
                console.log('return at', thiz.returnAddress.sub(m.base));
                thiz.outbuffer = args[1];
                fridautils.dumpMemory(thiz.outbuffer, 0x16*4);
                console.log('val 0x0e', thiz.outbuffer.add(0xe*4).readPointer());
                console.log('val 0x0f', thiz.outbuffer.add(0xf*4).readPointer());
            }, leaveFun:function(retval:NativePointer,tstr:string, thiz:any, userdata:any){
                //fridautils.dumpMemory(thiz.outbuffer, 0x16*4);
            }, },

            {enable:false,loc:0x6411b, nparas:4, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){ }, leaveFun:function(retval:NativePointer,tstr:string, thiz:any, userdata:any){}, },

            //{enable:false, loc:0x6a159, nparas:4, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
            //    let m = Process.getModuleByName(soname);
            //    console.log('return at', thiz.returnAddress.sub(m.base));
            // }, leaveFun:function(retval:NativePointer,tstr:string, thiz:any, userdata:any){
            //    fridautils.dumpMemory(retval, 0x16*4)
            //    console.log('check virtual funions');
            //    const vtable = retval.readPointer();
            //    fridautils.dumpMemory(vtable, 0x40);
            //    let m = Process.getModuleByName(soname)
            //    console.log('0x14 fun', vtable.add(0x14).readPointer().sub(m.base));
            //    console.log('0x3c fun', vtable.add(0x3c).readPointer().sub(m.base));
            // }, },
            {enable:false,loc:0x6a159, nparas:4, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
                let m = Process.getModuleByName(soname);
                console.log(tstr, 'return at', thiz.returnAddress.sub(m.base));
             }, leaveFun:function(retval:NativePointer,tstr:string, thiz:any, userdata:any){
                const p = retval;
                if(p.add(0x0e*4).readU32()!=0){
                    console.log(tstr, 'got list0')
                }
             }, },

            {enable:true,loc:0x6b14d, nparas:4, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
                show = true;
             }, leaveFun:function(retval:NativePointer,tstr:string, thiz:any, userdata:any){
                show = false;
             }, },
        ]
        console.log('hook funs');
        fridautils.hookFunList(funs, soname, {});
        // let funs1 = [
        //     {enable:false,loc:"strstr", nparas:4, hide:true, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
        //         if(show){
        //             const s1 = args[0].readUtf8String();
        //             const s2 = args[1].readUtf8String();
        //             console.log(tstr, s1, '$', s2)
        //         }
        //      }, leaveFun:function(retval:NativePointer,tstr:string, thiz:any, userdata:any){}, },
        //     {enable:true,loc:"fopen", nparas:4, hide:true, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
        //         if(show) {
        //             const path = args[0].readUtf8String();
        //             console.log(tstr, 'path', path);
        //             {
        //                 
        //             }
        //         }
        //      }, leaveFun:function(retval:NativePointer,tstr:string, thiz:any, userdata:any){}, },
        // ];
        // fridautils.hookFunList(funs1, "libc.so", {});
        console.log('add breakpts')
        let m = Process.getModuleByName(soname)
        const newCode = hook.code.link(m.base.add(0x6b1c0), new Map<string, NativePointer>([
            ["myputs", myputs],
            ]), true);
        console.log('newCode', newCode);               
        fridautils.dumpMemory(m.base.add(0x6b1c0),0x20);
    }, function(){});
}

var test0 = function(){
        let funs= [
// {enable:true, loc:'JNI_OnLoad', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:object, userdata:any){}, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },
            {enable:true, loc:'open', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
                console.log('path', args[0].readUtf8String())
                let m = Process.getModuleByName(soname);
                console.log(tstr, 'call at', thiz.returnAddress.sub(m.base))
            }, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },
            {enable:false, loc:'fopen', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:any, userdata:any){
                console.log(tstr,'path', args[0].readUtf8String());
                let m = Process.getModuleByName(soname);
                console.log(tstr, 'call at', thiz.returnAddress.sub(m.base))
            }, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },

            {enable:false,loc:'dlopen', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:object, userdata:any){
                const path = args[0].readUtf8String();
                console.log(tstr, "path", path);
            }, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){

            }, },
        ]
        console.log('hook funs');
        fridautils.hookFunList(funs, 'libc.so', {});
    
}

var test0 = ()=>{
    const m = Process.getModuleByName('libart.so');
    m.enumerateSymbols()
        .filter(e=>{return e.type=='function'})
        .filter(e=>{return e.name.includes("OpenFile") || e.name.includes("OpenMemory")})
        .forEach(e=>{
            // console.log(e.name);
            console.log(JSON.stringify(e))
        });
}

var test0 = ()=>{
    // _ZN3art7DexFile8OpenFileEiPKcbPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE
    // _ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_
    // _ZN3art2OS17OpenFileWithFlagsEPKci

    fridautils.hookDlopen("libnesec.so",()=>{
        var funs = [
// {enable:true, loc:'JNI_OnLoad', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:object, userdata:any){}, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },

{enable:true, loc:'_ZN3art7DexFile8OpenFileEiPKcbPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE', nparas:5, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:object, userdata:any){
    const location = args[2].readUtf8String();
    console.log('location', location)
}, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },

{enable:true, loc:'_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:object, userdata:any){}, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },
{enable:true, loc:'_ZN3art2OS17OpenFileWithFlagsEPKci', nparas:2, hide:false, enterFun:function(args:NativePointer[],tstr:string, thiz:object, userdata:any){}, leaveFun:function(retval:NativePointer,tstr:string, thiz:object, userdata:any){}, },
        ];
        fridautils.hookFunList(funs,"libart.so", {});
    }, ()=>{});

};




console.log('hello world')
test0()
