
#include <stdio.h>

// #define LOG_INFOS(fmt, args...)                                       \
// do{                                                                   \
//     char buff[0x200];                                                 \
//     snprintf(buff, 0x200, "[%s:%d]" fmt "\n", __FILE__, __LINE__, ##args);  \
//     frida_log(buff);                                                  \
// }while(0)

#define LOG_INFOS(fmt, args...)                                                 \
do {                                                                            \
    __android_log_print(3, "MyTest", "[%s:%d]", __FILE__, __LINE__, ##args);    \
}while(0) 

extern "C" void frida_log(const char*);

extern "C" int dumpSelfMap()
{
    char line[0x200];
    FILE* fp= fopen("/proc/self/maps", "r");
    if(fp!=NULL) {
        while (fgets(line, 0x200, fp)!=NULL){
            frida_log(line);
        }
        fclose(fp);
    }
    else{
        frida_log("can not open /proc/self/maps");
    }
    return 0;
}

extern "C" int __android_log_print( int prio, const char *tag, const char *fmt, ...);
static int test1(){
    
    return 11;
}
extern "C" void test0()
{
    test1();
    LOG_INFOS("called");
    return ;
}

