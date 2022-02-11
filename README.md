# readme
This is a project try to add code to existing process, and it's based on frida.

### introduction
Frist, I should say frida is totaly worthy of its decription, 'world class'. Yes, it's a world class dynamic instructmentation toolkit. 

Its new feature [CModule](https://frida.re/docs/javascript-api/#cmodule) is very impressed me. User can write a function in C, and link to current process, and try to call it at anytime, just like the following 
```typescript
const cm = new CModule(`
#include <stdio.h>

void hello(void) {
  printf("Hello World from CModule\\n");
}
`);

console.log(JSON.stringify(cm));

const hello = new NativeFunction(cm.hello, 'void', []);
hello();
```

But CModule has some issues:

1. The compilation is not very easy, sometimes, frida give me error messages, but I can not found the location of the error statement.
2. The running is not very stable, process teminates sometimes, but I don't know way. 

So I write this project for implement my own CModule, althghout it's in very beta pharse currently. I wrote this project in Typescript primarily, and I wrote a simple Python tool to convert a C/C++ code to a typescript module so frida can use it easily. This Python tools is in in scripts folder, and named c2tsmodule.py

### How to prepare C/C++ code 
I wrote a C++ file named hook0.cpp for testing, users write multiple function int your cpp file, and it'd better only one c++ source code for one module, I find compilation multiple c++ source files to one object file is not very easy.

### How to convert C/C++ code to typescript
Use c2tsmodule.py script in scripts folder.
```python

from ThumbCModuleConverter import *

converter = ThumbCModuleConverter();
converter.run('hook0.cpp', 'hook0.ts')  # convert hook0.cpp to hook0.ts as a typescript module for frida to use.

```
## Note
c2tsmodule.py use ARM cross compiler to compile source code file to a object file, so users need to install ARM cross compiler toolkit first. I use arm-linux-gnueabihf-gcc on Ubuntu.

### How to use it 

hook0.ts export a typescript function makeCode to put compiled binary into the process space

and hook0 module have a C++ function 'test0' 

The test code for for call function 'test0' in hook0 module

```Typescript

import * as hook0 from  './hook0'
// makeCode signature 
// makeCode = ( externalSymbols?: Map<string, NativePointer>| undefined )

// test0 may call some functions have loaded in process module, just like printf, users need to pass the address of these called extern function to hook0 module 

// the NativeCallback is actually function load in process memory, but it is written in javascript
const frida_log_fun = new NativeCallback( (s)=>{
            const ss = s.readUtf8String();
            console.log(ss)
        },'void', ['pointer']);
// frida_log_fun is a NativePointer,


let code = hook0.makeCode( new Map[
    // test0 function may call frida_log to print debug message. printf and __android_log_print can not print message to frida.
    ['frida_log',  frida_log_fun],  
]);

// find tset0 to call;
let test0_ptr = code.symbols.get('test0');
if(test0_ptr!=null){
    let test_fun = new NativeFunction(test0_ptr, 'void' : []);
    test_fun();
}


```

## ***
## following is the original readme 
## ***
### How to compile & load

```sh
$ git clone git://github.com/oleavr/frida-agent-example.git
$ cd frida-agent-example/
$ npm install
$ frida -U -f com.example.android --no-pause -l _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
