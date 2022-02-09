import * as fridautils from './fridautils'
import * as hook from './hook0'
import * as path from 'path'

const fs = require('frida-fs');

var soname = 'libgame.so'

var test0 = function(){
    Process.enumerateModules()
        .forEach(m=>{
            console.log(JSON.stringify(m))
        })
}

var test0 = function() {
    // write a cmoule to decrypt asset
    // const bt_decrypt_fun = Module.getExportByName(soname, '_Z10bt_decryptPhPm')
    // console.log('bt_decrypt_fun', JSON.stringify(bt_decrypt_fun))

    Process.getModuleByName(soname)
        .enumerateSymbols()
        // .filter(e=>{return e.name.includes("xxtea_decrypt")})
        .forEach(e=>{
            console.log(JSON.stringify(e))
        })
}

var test0 = function() {
    // write a cmoule to decrypt asset
    const decrypt_fun = Module.getExportByName(null, 'xxtea_decrypt')
    console.log('decrypt_fun', JSON.stringify(decrypt_fun))
}

var test0 = function() {
    Process.getModuleByName(soname)
        .enumerateSymbols()
        .forEach(e=>{
            console.log(JSON.stringify(e))
        })
}

var test0 = function() {
    // write a cmoule to decrypt asset
    // const bt_decrypt_fun = Module.getExportByName(soname, '_Z10bt_decryptPhPm')
    //console.log('bt_decrypt_fun', JSON.stringify(bt_decrypt_fun))

    fridautils.hookDlopen(soname,()=>{
        const bt_decrypt_fun = Module.getExportByName(soname, '_Z10bt_decryptPhPm')
        console.log('bt_decrypt_fun', JSON.stringify(bt_decrypt_fun))
    },()=>{})

}


var test0 = function() {
    const bt_decrypt_fun = Module.getExportByName(soname, '_Z10bt_decryptPhPm')
    console.log('bt_decrypt_fun', JSON.stringify(bt_decrypt_fun))

    // call bt_decrypt
    const cm = new CModule(`
        #include <stdio.h>
        extern void frida_log(char*);
        void hello(void) {
            frida_log("Hello World from CModule\\n");
        }
    `, {
        "frida_log" : new NativeCallback(
            (s)=>{
                const ss = s.readUtf8String();
                console.log(ss)
            },'void', ['pointer']
        ),
    });

    console.log(JSON.stringify(cm));
    const hello = new NativeFunction(cm.hello, 'void', []);
    hello();
    
}


console.log('hello world')
test0()
