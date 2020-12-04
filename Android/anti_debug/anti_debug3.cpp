//
// Created by alien on 2020-12-03.
//


#include "anti_debugging.h"

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    anti_debugging5();
    return JNI_VERSION_1_6;
}

///////////////////////////////   1. tracepid 단일 check test.
void *check_tracepid(void *) {
    char *status_path="proc/self/status";
    char readbuf[100] = { 0 };

    int fd = openat( NULL , status_path, O_RDONLY);

    read(fd, readbuf, 100);
    close(fd);
    uint8_t *start = (uint8_t *) readbuf;
    uint8_t des[100] = { 0x54, 0x72, 0x61, 0x63, 0x65, 0x72, 0x50, 0x69, 0x64, 0x3A,0x09 };
    int i = 100;
    int flag;

    while (--i)
    {
        if( !memcmp(start,des,10) )
        {
            start = start+11; //"TracePid: " 까지가 10단어.
            flag=atoi((char*)start);
            break;
        }else
        {
            start=start+1;
        }
    }
    LOGD("[*] TracePid : %d",flag);

    return 0;
}

void anti_debugging1(){
    pthread_t anti_debugging;
    pthread_attr_t attrib;

    pthread_attr_init(&attrib);
    pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_DETACHED); // join 필요 없게..

    pthread_create(&anti_debugging,&attrib,check_tracepid,(void*)NULL);
    pthread_setname_np(anti_debugging, "mem-monitor");
    LOGD("[*] mem-check_tracepid is created");
}

////////////////////////////// 2. parent name check - 실패 권한 문제.
void anti_debugging2()
{
    // Set up buf
    char ppid_cmdline[0x100] = {0};
    snprintf(ppid_cmdline, sizeof(ppid_cmdline), "/proc/%d/cmdline", getppid());

    // open a file
    int fd = open("/proc/1684/cmdline", O_RDONLY);
    if (fd < 0)
    {
        LOGD("CheckParents open error!\n"); //권한이 없어서 안되나?
        return;
    }

    // File content read into memory
    memset(ppid_cmdline, 0, sizeof(ppid_cmdline)); // ppid_cmdline을 그냥 계속 활용하네..
    ssize_t ret = read(fd, ppid_cmdline, sizeof(ppid_cmdline));
    if (-1 == ret)
    {
        LOGD("CheckParents read error!\n");
        return;
    }

    // Not found return 0
    char* sRet = strstr(ppid_cmdline, "zygote");
    if (NULL == sRet)
    {
        // Execution to here, judged as debugging state
        LOGD(" Parent process cmdline No zygote Substring!\n");
        return;
    }
    LOGD("2. anti-debuggin : zygote ");
    return;
}

////////////////////////////// 3. task 개수 세기
int get_task_count()
{
    DIR *dir;
    struct dirent *entry;
    pid_t tid;
    int count=0;

    dir = opendir("/proc/self/task");
    if (dir == NULL) return 0; // 일단 예외처리는 보류

    while((entry = readdir(dir)) != NULL) {
        tid = atoi(entry->d_name);
        if (tid != 0 ) count++;
    }
    closedir(dir);
    return count;
}
void anti_debugging3() {
    LOGD("anti_debugging3 %d",get_task_count());
    return;
}
////////////////////////////// 4. reflection
void anti_debugging4(JNIEnv* env){
    jclass c = env->FindClass("android/os/Debug");
    jboolean bResult = false;

    jmethodID is_debugged = env->GetStaticMethodID(c, "isDebuggerConnected", "()Z");
    if( is_debugged ) {
        bResult = env->CallStaticBooleanMethod(c, is_debugged);
    }
    if(bResult) LOGD("Debugger attached");
    else LOGD("Nomal");
    return;
}

////////////////////////////// 5. signal -일단은 mutex로..
int a=0;
void my_sigtrap(int sig)
{
 a=1;
 LOGD("release mutex");
}
void anti_debugging5(){
    signal(SIGTRAP, my_sigtrap);
    raise(SIGTRAP);
    if(a)
        LOGD("MAIN LOGIC");
    else
        LOGD("DEBUG DETECT");
}
////////////////////////////// 6. time base
int _time()
{
    time_t t1, t2;
    time(&t1);
    /* breakpoint */
    time(&t2);
    if (t2 - t1 > 2)
    {
        LOGD("debugged");
    }else{
        LOGD("not-debugged");
    }
    return 0;
}
void anti_debugging6(){
    _time();
}
