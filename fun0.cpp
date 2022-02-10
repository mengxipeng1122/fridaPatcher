
#include <stdio.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
extern "C" void frida_log(const char*);

#define LOG_INFOS(fmt, args...)                                       \
do{                                                                   \
    char buff[0x200];                                                 \
    snprintf(buff, 0x200, "[%s:%d]" fmt "\n", __FILE__, __LINE__, ##args);  \
    frida_log(buff);                                                  \
}while(0)

#define LOG_ERRS(fmt, args...)                                       \
do{                                                                   \
    char buff[0x200];                                                 \
    snprintf(buff, 0x200, "[%s:%d]" fmt "\n", __FILE__, __LINE__, ##args);  \
    frida_log(buff);                                                  \
    exit(-1);             \
}while(0)


////////////////////////////////////////////////////////////////////////////////
// declaration of utils 

static unsigned char* readInputFile(const char* fn, unsigned long& len);
static int writeOutputFile(const char* fn, unsigned char* data, unsigned long sz);


////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// 
unsigned char* readInputFile(const char* fn, unsigned long& le)
{
    FILE* fp =  fopen(fn, "rb");
    if(!fp) LOG_ERRS("can not open file %s for reading ", fn);
    fseek(fp, 0, SEEK_END);
    le = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned long buffer_length = le+0x10; // allocate more bytes for avoid error 
    unsigned char* buffer = new unsigned char [buffer_length];
    memset(buffer, 0, buffer_length);
    size_t read = fread(buffer, 1, le, fp);
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

extern "C" int _Z10bt_decryptPhPm(void*, void*);
int _fun()
{
    LOG_INFOS(" go  here");
    unsigned long input_le; 
    unsigned char* input_buffer= readInputFile("test.in", input_le);
    unsigned long output_le=input_le;
    int ret = _Z10bt_decryptPhPm(input_buffer,  &output_le);
    LOG_INFOS("bt_decrypt return %d and output length %lu", ret, output_le);
    writeOutputFile("test.out", input_buffer, output_le);

    return 0;
}

#define TESTDIR "/storage/emulated/0/"
extern "C" int test0 ()
{
    // 
    LOG_INFOS(" go  here");
    unsigned long input_le; 
    unsigned char* input_buffer= readInputFile(TESTDIR "test.in", input_le);
    LOG_INFOS(" input_buffer %p , input_le %lu", input_buffer, input_le);
    unsigned long output_le=input_le;
    int ret = _Z10bt_decryptPhPm(input_buffer,  &output_le);
    if(ret == 1){
        LOG_INFOS("bt_decrypt return %d and output length %lu", ret, output_le);
        writeOutputFile(TESTDIR "test.out", input_buffer, output_le);
    }
    else{
        LOG_INFOS("bt_decrypt return failed");
    }
    return 0;
}

