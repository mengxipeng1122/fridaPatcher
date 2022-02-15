
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#if 1
#define LOG_INFOS(fmt, args...)                                       \
do{                                                                   \
    char buff[0x200];                                                 \
    snprintf(buff, 0x200, "[%s:%d]" fmt, __FILE__, __LINE__, ##args); \
    frida_log(buff);                                                  \
}while(0)
#else

#define LOG_INFOS(fmt, args...)                                                 \
do {                                                                            \
    __android_log_print(3, "MyTest", "[%s:%d]", __FILE__, __LINE__, ##args);    \
}while(0) 

#endif

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
    LOG_INFOS("call 1s");
    
    return 11;
}
static void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  char line[0x200];
  size_t offset = 0;
  for (i=0; i<buflen; i+=16) {
      sprintf(line+offset,"%06x: ", i); offset = strlen(line);
      for (j=0; j<16; j++)
      {
          if (i+j < buflen)
              sprintf(line+offset,"%02x ", buf[i+j]);
          else
              sprintf(line+offset,"     ");
          offset= strlen(line);
      }
      sprintf(line+offset," "); offset= strlen(line);
      for (j=0; j<16; j++)
      {
          if (i+j < buflen)
          {
              sprintf(line+offset,"%c", isprint(buf[i+j]) ? buf[i+j] : '.');
              offset= strlen(line);
          }
      }
      LOG_INFOS("%s",line);
      offset = 0;
  }
}

extern "C" void test0(void* sp)
{
    LOG_INFOS(" sp %p", sp);
    hexdump(sp, 0x200);
    return ;
}

