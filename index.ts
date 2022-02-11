import * as fridautils from './fridautils'
import * as path from 'path'
import * as fun0 from  './fun0'
import * as hook0 from  './hook0'

const fs = require('frida-fs');

const frida_log_fun = new NativeCallback( (s)=>{
            const ss = s.readUtf8String();
            console.log(ss)
        },'void', ['pointer']);


const test_log_fun = new NativeCallback(() =>{
            console.log('test called')
        },'void', []);
//const test_log_fun_fun= new NativeFunction(test_log_fun, 'void', []);

var test0 = function() {
    var hookptr= Module.getExportByName('libBlue.so', '_ZN18VuAssetFactoryImpl9loadAssetEPK15VuAssetTypeInfoP9VuAssetDBP7VuAsset');
    Interceptor.attach(hookptr,{
        onEnter:(args)=>{},
        onLeave:(retval)=>{},
    }) 

    fridautils.dumpMemory(hookptr);
    for(var i =0;i<4;i++){
        console.log(Instruction.parse(hookptr.sub(i*4)).toString());
    }
}


var test0 = function() {
    var hookptr= Module.getExportByName('libBlue.so', '_ZN18VuAssetFactoryImpl9loadAssetEPK15VuAssetTypeInfoP9VuAssetDBP7VuAsset');
    console.log('hookptr', hookptr);

    let {code, hooks} = hook0.hookCode( [
            { pos:hookptr.add(0x00), fun: 'test0'},
        ],
        new Map<string, NativePointer>([
            ["frida_log", frida_log_fun ],
        ]),
    );
    // show test0;

    {
            let funaddr = code.symbols.get('test0');
            if(funaddr!=null) {
        console.log('test0',funaddr)
         const test0_fun = new NativeFunction(funaddr, 'int', []);
         test0_fun();
            }
    }
    console.log(JSON.stringify(hooks)); 
    hooks.forEach(e=>{
        console.log('pos', e.pos);
        fridautils.dumpMemory(e.pos.sub(1), 0x10);
        {
            let fn = '/mnt/sdcard/'+e.pos.sub(1)+'.dump';
            fridautils.dumpMemoryToFile(e.pos.sub(1), 0x10, fn);
        }
        console.log(Instruction.parse(e.pos).toString());
        console.log('e.buffer', e.buffer);
        fridautils.dumpMemory(e.buffer, 0x100);
        {
            let fn = '/mnt/sdcard/'+e.buffer+'.dump';
            fridautils.dumpMemoryToFile(e.buffer, 0x100, fn);
        }
    })



    // Interceptor.attach(hookptr.add(0x22+8),{
    //     onEnter:(args)=>{
    //         console.log('returned haha');
    //         },
    //     onLeave:(retval)=>{},
    // }) 


    // console.log("code.buffer", code.buffer, code.bufferLength);
    // fridautils.dumpMemory(code.buffer);
    // let test0_ptr = code.symbols.get('test0');
    // if(test0_ptr!=null) {
    //     const test0_fun = new NativeFunction(test0_ptr, 'int', []);
    //     test0_fun();
    // }
}

var test0 = function() {
    var hookptr= Module.getExportByName('libBlue.so', '_ZN18VuAssetFactoryImpl9loadAssetEPK15VuAssetTypeInfoP9VuAssetDBP7VuAsset');
    Interceptor.attach(hookptr.add(0x0),{
        onEnter:(args)=>{
const test_log_fun_fun= new NativeFunction(test_log_fun, 'void', []);
    //     test_log_fun_fun();
     //       console.log('call haha');
        },
        onLeave:(retval)=>{},
    }) 

    let dumpInfos = [];

    // check memory
    let jumpTo;
    {
        console.log('hookptr', hookptr);
        fridautils.dumpMemory(hookptr.sub(1))
        console.log(Instruction.parse(hookptr.sub(0).add(0x00)).toString());
        dumpInfos.push({p:hookptr.sub(1), n:0x10});
        jumpTo = hookptr.sub(1).add(4).readPointer();
        let range = Process.findRangeByAddress(jumpTo);
        console.log('jumpTo',jumpTo);
        console.log('range',range);
    }
//ab734000-ab735000 r--p 00000000 00:00 0 
//ab735000-ab73c000 rwxp 00000000 00:00 0 
//ab73c000-ab74c000 rw-p 00000000 00:00 0 
    {
        const addr = ptr(0xab730000);
        const le = 0x21000
        dumpInfos.push({p:addr, n:le});
    
    }
    // {
    //     //jump1
    //     const addr= jumpTo;
    //     fridautils.dumpMemory(addr.sub(1));
    //     fridautils.showAsmCode(addr, 10);
    //     dumpInfos.push({p:addr.sub(1), n:0x100});
    //     jumpTo = addr.sub(1).add(0x14).readPointer();
    //     const dataaddr = addr.sub(1).add(0x10).readPointer();
    //     fridautils.dumpMemory(dataaddr)
    //     dumpInfos.push({p:dataaddr, n:0x80});
    // }
    // {
    //     //jump2
    //     let  addr = jumpTo;
    //     fridautils.dumpMemory(addr.sub(1));
    //     fridautils.showAsmCode(addr, 10);
    //     dumpInfos.push({p:addr.sub(1), n:0x100});
    //     jumpTo = addr.sub(1).add(0x54).readPointer();
    // }
    // {
    //     //jump3
    //     let  addr = jumpTo;
    //     fridautils.dumpMemory(addr.sub(1));
    //     fridautils.showAsmCode(addr, 10);
    //     dumpInfos.push({p:addr.sub(1), n:0x100});
    //     jumpTo = addr.add(0xa000);
    // }
    // {
    //     //jump3
    //     let  addr = jumpTo;
    //     fridautils.dumpMemory(addr.sub(1));
    //     fridautils.showAsmCode(addr, 10);
    //     dumpInfos.push({p:addr.sub(1), n:0x100});
    // }
    // dump memorys
    {
        dumpInfos.forEach(d=>{
            let addr = d.p;
            let le = d.n;
            let fn = "/mnt/sdcard/"+addr+'.dump'
            fridautils.dumpMemoryToFile(addr, le, fn);
        })
        {
            let s = JSON.stringify(dumpInfos);
            let n = s.length;
            let sbuf=Memory.allocUtf8String(s);
            fridautils.dumpMemory(sbuf, 0x80);
            console.log('n',ptr(n));
            let fn = "/mnt/sdcard/dumpInfos.json"
            fridautils.dumpMemoryToFile(sbuf, n, fn);
        }
    }
}

var test0 = function() {
    var hookptr= Module.getExportByName('libBlue.so', '_ZN18VuAssetFactoryImpl9loadAssetEPK15VuAssetTypeInfoP9VuAssetDBP7VuAsset');

    let {code, hooks} = hook0.hookCode( [
            { pos:hookptr.add(0x14), fun: 'test0'},
        ],
        new Map<string, NativePointer>([
            ["frida_log", frida_log_fun ],
        ]),
    );

    //{
    //        // show test0;
    //        let funaddr = code.symbols.get('test0');
    //        if(funaddr!=null) {
    //            console.log('test0',funaddr)
    //            const test0_fun = new NativeFunction(funaddr, 'int', []);
    //            test0_fun();
    //        }
    //        return ;
    //}

    console.log(JSON.stringify(hooks)); 
    let dumpInfos: { p: NativePointer; n: number; }[] = [];
    dumpInfos.push({p:hookptr.sub(1),n:0x10})
    hooks.forEach(e=>{
        console.log('pos', e.pos);
        dumpInfos.push({p:e.pos.sub(1),n:0x10})
        dumpInfos.push({p:e.buffer,n:0x100})
    })

    {
        dumpInfos.forEach(d=>{
            let addr = d.p;
            let le = d.n;
            let fn = "/mnt/sdcard/"+addr+'.dump'
            fridautils.dumpMemoryToFile(addr, le, fn);
        })
        {
            let s = JSON.stringify(dumpInfos);
            let n = s.length;
            let sbuf=Memory.allocUtf8String(s);
            fridautils.dumpMemory(sbuf, 0x80);
            console.log('n',ptr(n));
            let fn = "/mnt/sdcard/dumpInfos.json"
            fridautils.dumpMemoryToFile(sbuf, n, fn);
        }
    }



    

}

console.log('hello world')
test0()
