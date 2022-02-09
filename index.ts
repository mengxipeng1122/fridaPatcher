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

        #include <string.h>
        #include <stdio.h>
        #include <stdlib.h>

        extern void *fopen( char *pathname, const char *mode);

        extern void frida_log(char*);

        #define LOG_INFOS(fmt, args...)                                       \
        do{                                                                   \
            fprintf(stdout, "[%s:%d]" fmt "\n", __FILE__, __LINE__, ##args);  \
            fflush(stdout);                                                   \
        }while(0)

        #define LOG_ERRS(fmt, args...)                                       \
        do{                                                                   \
            fprintf(stderr, "[%s:%d]" fmt "\n", __FILE__, __LINE__, ##args);  \
            fflush(stderr);                                                   \
        }while(0)


        void hello(void) {
            frida_log("Hello World from CModule\\n");
        }

        unsigned char* readInputFile(const char* fn, unsigned long* le)
        {
            FILE* fp =  fopen(fn, "rb");
            if(!fp) LOG_ERRS("can not open file %s for reading ", fn);
            fseek(fp, 0, SEEK_END);
            *le = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            unsigned long buffer_length = *le+0x10; // allocate more bytes for avoid error 
            unsigned char* buffer = new unsigned char [buffer_length];
            memset(buffer, 0, buffer_length);
            size_t read = fread(buffer, 1, *le, fp);
            LOG_INFOS("read %u bytes from %s to %p ", read, fn, buffer);
            fclose(fp);
            return buffer;
        }

        int writeOutputFile(const char* fn, unsigned char* data, unsigned long sz)
        {
            if(!data) LOG_ERRS("data %p is invalid", data);
            FILE* fp = fopen(fn, "wb");
            if(!fp) LOG_ERRS("can not open file %s for writing ", fn);
            size_t wrote = fwrite( data, 1, sz, fp);
            LOG_INFOS("wrote %u bytes from %p to %s ", wrote, data, fn);
            fclose(fp);
            return 0;
        }


        void test(void) {
            frida_log("this is test");
        }
        
    `, {
        "frida_log" : new NativeCallback(
            (s)=>{
                const ss = s.readUtf8String();
                console.log(ss)
            },'void', ['pointer']
        ),
        "fopen" : Module.getExportByName(null, "fopen"),
    });

    console.log(JSON.stringify(cm));
    const test = new NativeFunction(cm.test, 'void', []);
    console.log(test, JSON.stringify(test));
    test();
    
}


console.log('hello world')
test0()
