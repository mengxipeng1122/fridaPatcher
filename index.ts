import * as fridautils from './fridautils'
import * as path from 'path'
import * as hook0 from  './hook0'
const fs = require('frida-fs');

let frida_log_callback =  new NativeCallback(function(sp:NativePointer){
    let s = sp.readUtf8String();
    console.log(s);
}, 'void', ['pointer']);

var test0 = ()=>{
    let show=false;
    let dumped = false;
    let hooks:InvocationListener[] = [];
    // find open memory function
    fridautils.hookRegisterNatives("com.netease.nis.wrapper.MyJni", new Map([
        ["load", {
            onEnter:(args)=>{
                console.log('enter load');
                show=true;
                let offset = 0xa1114219  - 0xa10af000;
                let address = Module.getBaseAddress('libnesec.so').add(offset);
                // fridautils.hookFunList(infos, hooks);
                let hooks:hook0.HookOption[]=[
                    {pos:address,fun:"test0"},
                ];
                hook0.hookCode(hooks,new Map<string, NativePointer>([
                    ["frida_log", frida_log_callback],
                ]))

                
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
