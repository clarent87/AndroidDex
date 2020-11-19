/* 안티디버깅 대강 list up
1. IDA Debug port detection : /proc/net/tcp의 port list확인 >> 이건 제외
2. Debugger process name detection : ps로 process 이름 확인 >> 이건 제외
3. Parent process name detection >> ida도 gdbserver였던거 같은데.. 확인 필요
   : 기본적으로 gdbserver 로 so debugging시에는 parent가 zygote가 아닌가봄
   : lldb같은걸로 apk debugging시에는 zygote고.. 
4. Own process name detection : 위와 비슷 cmdl에서 apk 네임이 com.xxx 같은게 맞는지 test >> 이건 제외
5. apk Thread detection : so만 debugging하려고 executable 따로 만들면 thread가 하나니까..  >> 요건 debugging 환경 구축하고 확인 필요
6. apk process fd File detection >> 일단 제외
   : apk 랑 그냥 exe랑 fd 갯수가 다르고, debug 랑 아닌거랑 fd 갯수가 다르다고 함
7. Android system comes with debug detection function >> 이건 제외
   : 그냥 android 에서 제공하는 isDebuggerConnected  함수를 native에서 호출하는 방법
   : dlopen으로 열고 dlsym으로 직접 찾아서 호출하는 방식 
   : 물론 dalvik은 되고 art는 안된다함 ( 그.. namespace 때문인듯)
   : 이거 gdb같은것도 detect가 되나?
8. ptrace Detect : 이건 뻔한거 >> 제외
9. function hash Value detection >> 일단 보류
   : 이거 function instruction hash 계산하겠다는건데, bp걸리면 바뀌니까..
   : 근데 그럼 hash를 미리 계산해둬야 하는데.. arch 마다.. 
   : 그럼 해당 file 빌드때마다 확인해줘야할거 같음. 자동화 하기가 애매할듯 
   : elf의 function size가 안맞을 때가 있다던데.. 이거 아닌거 같은데.. 

10.Breakpoint instruction detection >> 이건 해볼만 할거 같긴한데.. 
   : 특정 함수에 대해 bp 걸렸는지 scan
   : arm, thumb, arm64 bp instruction 확인 필요
   : 여기 예에서는 function size도 param으로 필요 즉, function size 확인 방안 필요 ( strip 관련 내용 파악도 필요.)
   : 짜피.. size는 쫌 틀려도 로직 돌리는데에는 갠춘할듯.
11. System source code modification detection >> 이건 진행( 물론 쓸지는 모르겠다.) 
   : tracepid 읽는거. 적당히 ptrace랑 엮임
   : 이거 쓰려면 parent에서도 child 생성을 check
   : 그리고 ida에서 parent에 attach하면 child도 멈추던데? 이러면 사실 큰 의미 없을 수도.. 
   : 즉 parent에서도 무언가가 필요..
   https://github.com/clarent87/AndroidAntiDebugger/ => flag 기반
   https://github.com/clarent87/Android_Anti_Debug/  => 기존에 보던거?
   : notion에 anti-debug쪽 link check 필요( 거기 있는 것들의 거의 종합인듯. )

12 Single step debugging trap >> 한번정도 검토 필요
   : x86과 seh유사한 듯, signal 생성하고 debugger 없었다면 시그널 핸들러에서 처리하고 넘어감
   : 디버거가 붙었다면 signal은 디버거가 처리 (또는 target으로 재전달 가능할거 같은데..)
   : 여기서 signal handler의 처리 로직이 중요한데.. 디버거가 하는 작업과 동일하게 진행 ( break point의 instruct을 nop으로 수정하고 pc이동)
   : 근데 이거 code 영역에 write 권한 필요할듯.. 괜찮나.. PC이동도 arm64는 direct로 되지는 않을텐데..
   : 이거 보니까 heap이네.. heap에 execution 가능한가? android 에서?
    * 디버거 원리
      일단 target 위치의 instruction save
      해당 위치 instruction 을 bp로 변경
      bp 걸림
      signal 받고 debugging 작업
      원본 instruction 복원
      pc를 원본 instruction위치로 돌림 ( 이래야 제대로 프로그램이 돌겠지)

13.  use IDA First intercept signal characteristic detection
   : http://egloos.zum.com/studyfoss/v/5182475
   : 이거 12랑 비슷 단 12는 pb를 이용한거고 이건 raise로 signal을 직접 전달.
14 use IDA Analyze defects and anti-debug >> 한번 해보면 좋을듯.
    : ida가 재귀 하향식이라서 indirect code paths는 핸들링이 안된다고함.. 이걸 이용한 공격
    : 동적으로 계산되는 jump 및 arm thumb 썩인 switch같은것들.. 이 분석이 안되나봄.. ( 지금도 그런가?)
    : 이거 debugging에서도 문제를 내준다네.. 
    : 코드가 정확히 이해되진 않네.. 

15 Five types of code execution time detection >> 이건 추가
    : 시간으로 측정 ( api가 5개 정도 잇음)
    : 어느 위치에 넣을지가 중요하겠네.. ( 혹시 일반적인 상황에서도 오탐이 있을지? )
    : 이부분은 다른 솔루션 참조 해야 할듯.. 거 뭐 있엇음
16 Three types of process information structure detection
17 Inotify Event monitoring dump
    : dd versus gdb_gcore Come dump로도 패킹 풀어진 내용 가져올수 있나봄?
*/

// 3. Parent process name detection
void CheckParents()
{
    ///////////////////
    // Set up buf
    char strPpidCmdline[0x100] = {0};
    snprintf(strPpidCmdline, sizeof(strPpidCmdline), "/proc/%d/cmdl ine", getppid());
    // open a file
    int file = open(strPpidCmdline, O_RDONLY);
    if (file < 0)
    {
        LOGA("CheckParents open error!\n");
        return;
    }
    // File content read into memory
    memset(strPpidCmdline, 0, sizeof(strPpidCmdline));
    ssize_t ret = read(file, strPpidCmdline, sizeof(strPpidCmdline));
    if (-1 == ret)
    {
        LOGA("CheckParents read error!\n");
        return;
    }
    // Not found return 0
    char sRet = strstr(strPpidCmdline, "zygote");
    if (NULL == sRet)
    {
        // Execution to here, judged as debugging state
        LOGA(" Parent process cmdline No zygote Substring!\n");
        return;
    }
    int i = 0;
    return;
}

// 5. apk Thread detection
void CheckTaskCount()
{
    char buf[0x100] = {0};
    char *str = "/proc/%d/task";
    snprintf(buf, sizeof(buf), str, getpid());
    // open Directory:
    DIR *pdir = opendir(buf);
    if (!pdir)
    {
        perror("CheckTaskCount open() fail.\n");
        return;
    }
    // View the number of files in the directory:
    struct dirent *pde = NULL;
    int Count = 0;
    while ((pde = readdir(pdir)))
    {
        // Character filter
        if ((pde->d_name[0] <= '9') && (pde->d_name[0] >= '0'))
        {
            ++Count;
            LOGB("%d Thread name:% s\n", Count, pde->d_name);
        }
    }
    LOGB(" The number of threads is:% d", Count);
    if (1 >= Count)
    {
        // It is judged as the debugging state here.
        LOGA(" Debugging status!\n");
    }
    int i = 0;
    return;
}

// 10. Breakpoint instruction detection
// IDA 6.8 Breakpoint scan
// parameter 1 : The first address parameter of the function 2 :function size
typedef uint8_t u8;
typedef uint32_t u32;
void checkbkpt(u8 *addr, u32 size)
{
    // result
    u32 uRet = 0;
    // Breakpoint instruction
    // u8 armBkpt[4]={0xf0,0x01,0xf0,0xe7};
    // u8 thumbBkpt[2]={0x10,0xde};
    u8 armBkpt[4] = {0};
    armBkpt[0] = 0xf0;
    armBkpt[1] = 0x01;
    armBkpt[2] = 0xf0;
    armBkpt[3] = 0xe7;
    u8 thumbBkpt[2] = {0};
    thumbBkpt[0] = 0x10;
    thumbBkpt[1] = 0xde;
    // Judgment Mode
    int mode = (u32)addr % 2;
    if (1 == mode)
    {
        LOGA("checkbkpt:(thumb mode)该地址为thumb模式\n");
        u8 *start = (u8 *)((u32)addr - 1);
        u8 *end = (u8 *)((u32)start + size);
        // Traversal comparison
        while (1)
        {
            if (start >= end)
            {
                uRet = 0;
                LOGA("checkbkpt:(no find bkpt)没有发现断点.\n");
                break;
            }
            if (0 == memcmp(start, thumbBkpt, 2))
            {
                uRet = 1;
                LOGA("checkbkpt:(find it)发现断点.\n");
                break;
            }
            start = start + 2;
        } //while
    }     //if
    else
    {
        LOGA("checkbkpt:(arm mode)该地址为arm模式\n");
        u8 *start = (u8 *)addr;
        u8 *end = (u8 *)((u32)start + size);
        // Traversal comparison
        while (1)
        {
            if (start >= end)
            {
                uRet = 0;
                LOGA("checkbkpt:(no find)没有发现断点.\n");
                break;
            }
            if (0 == memcmp(start, armBkpt, 4))
            {
                uRet = 1;
                LOGA("checkbkpt:(find it)发现断点.\n");
                break;
            }
            start = start + 4;
        } //while
    }     //else
    return;
}

// 11. System source code modification detection
bool checkSystem()
{
    // Build pipeline
    int pipefd[2];
    if (-1 == pipe(pipefd))
    {
        LOGA("pipe() error.\n");
        return false;
    }
    // Create child process
    pid_t pid = fork();
    LOGB("father pid is: %d\n", getpid());
    LOGB("childpid is: %d\n", pid);
    // for failure
    if (0 > pid)
    {
        LOGA("fork() error.\n");
        return false;
    }
    // Subprocess program
    int childTracePid = 0;
    if (0 == pid)
    {
        int iRet = ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (-1 == iRet)
        {
            LOGA("child ptrace failed.\n");
            exit(0);
        }
        LOGA("%s ptrace succeed.\n");
        // Obtain tracepid
        char pathbuf[0x100] = {0};
        char readbuf[100] = {0};
        sprintf(pathbuf, "/proc/%d/status", getpid());
        int fd = openat(NULL, pathbuf, O_RDONLY);
        if (-1 == fd)
        {
            LOGA("openat failed.\n");
        }
        read(fd, readbuf, 100);
        close(fd);
        uint8_t *start = (uint8_t *)readbuf;
        uint8_t des[100] = {0x54, 0x72, 0x61, 0x63, 0x65, 0x72, 0x5 0, 0x69, 0x64, 0x3A, 0x09};
        int i = 100;
        bool flag = false;
        while (--i)
        {
            if (0 == memcmp(start, des, 10))
            {
                start = start + 11;
                childTracePid = atoi((char *)start);
                flag = true;
                break;
            }
            else
            {
                start = start + 1;
                flag = false;
            }
        } //while
        if (false == flag)
        {
            LOGA("get tracepid failed.\n");
            return false;
        }
        // Write data to the pipeline
        close(pipefd[0]);
        write(pipefd[1], (void *)&childTracePid, 4); // Write to the pipe writer
                                                     // Close the pipe read end data
        close(pipefd[1]);                            // Close the pipe to write after writing end
        LOGA("child succeed, Finish.\n");
        exit(0);
    }
    else
    {
        // Parent process program
        LOGA(" Start waiting for the child process.\n");
        waitpid(pid, NULL, NULL); // Wait for child process End
        int buf2 = 0;
        close(pipefd[1]);
        read(pipefd[0], (void *)&buf2, 4);
        // Close the writer
        // Read from the reader Data to buf
        close(pipefd[0]);
        LOGB(" The content passed by the child process is:% d\n", buf2);
        // Judging the child process ptarce After tracepid
        if (0 == buf2)
        {
            LOGA(" The source code has been modified.\n");
        }
        else
        {
            LOGA(" The source code has not been modified.\n");
            // Close the reader
            // Output content
        }
        return true;
    }
}
void smain()
{
    bool bRet = checkSystem();
    if (true == bRet)
        LOGA("check succeed.\n");
    else
        LOGA("check failed.\n");
    LOGB("main Finish pid:%d\n", getpid());
    return;
}

// 12. Single step debugging trap
#!cpp
char dynamic_ccode[] = {0x1f, 0xb4,  //push {r0-r4}
                        0x01, 0xde,  //breakpoint => 여기서 signal이 걸리면 여기가 nop처리 되지 않는이상 계속 sigtrap인가봄( 디버거원리 생각해보면 당연)
                        0x1f, 0xbc,  //pop {r0-r4}
                        0xf7, 0x46}; //mov pc,lr
char *g_addr = 0;
void my_sigtrap(int sig)
{
    char change_bkp[] = {0x00, 0x46}; //mov r0,r0
    memcpy(g_addr + 2, change_bkp, 2);
    __clear_cache((void *)g_addr, (void *)(g_addr + 8)); // need to clear cache
    LOGI("chang bpk to nop\n");
}
void anti4()
{ //SIGTRAP
    int ret, size;
    char *addr, *tmpaddr;
    signal(SIGTRAP, my_sigtrap);
    addr = (char *)malloc(PAGESIZE * 2);
    memset(addr, 0, PAGESIZE * 2);
    g_addr = (char *)(((int)addr + PAGESIZE - 1) & ~(PAGESIZE - 1));
    LOGI("addr: %p ,g_addr : %p\n", addr, g_addr);
    ret = mprotect(g_addr, PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC); // 역시.. ( 근데 자세히 보니 code 영역은 아닌듯.. )
    if (ret != 0)
    {
        LOGI("mprotect error\n");
        return;
    }
    size = 8;
    memcpy(g_addr, dynamic_ccode, size);
    __clear_cache((void *)g_addr, (void *)(g_addr + size)); // need to clear cache
    __asm__("push {r0-r4,lr}\n\t"
            "mov r0,pc\n\t"    // at this time pc Point to the next two instructions
            "add r0,r0,#4\n\t" ///+4 Yes lr Address is pop{r0-r5}
            "mov lr,r0\n\t"
            "mov pc,%0\n\t"   // 여기서 부터는 pc가 g_addr로 변함
            "pop {r0-r5}\n\t" // g_addr 끝나고 여기로 옴
            "mov lr,r5\n\t"   // restore lr
            :
            : "r"(g_addr)
            :);

    LOGI("hi, i'm here\n");
    free(addr);
}

// 13.  use IDA First intercept signal characteristic detection
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
void myhandler(int sig)
{
    //signal(5, myhandler);
    printf("myhandler.\n");
    return;
}
int g_ret = 0;
int main(int argc, char **argv)
{
    // Set up SIGTRAP The signal processing function is myhandler()
    g_ret = (int)signal(SIGTRAP, myhandler);
    if ((int)SIG_ERR == g_ret)
        printf("signal ret value is SIG_ERR.\n");
    // print signal Return value (original processing function address)
    printf("signal ret value is %x\n", (unsigned char *)g_ret);
    // Actively send to your own process SIGTRAP signal
    raise(SIGTRAP); // signal 날리기 ( raise나 kill이나 같음 대신 kill은 getpid 줘야하고..)
    raise(SIGTRAP);
    raise(SIGTRAP);
    kill(getpid(), SIGTRAP); // signal 날리기
    printf("main.\n");
    return 0;
}

// 14.  use IDA Analyze defects and anti-debug
#if (JUDGE_THUMB)
#define GETPC_KILL_IDAF5_SKATEBOARD \
    __asm __volatile(               \
        "mov r0,pc \n\t"            \
        "adds r0,0x9 \n\t"          \
        "push {r0} \n\t"            \
        "pop {r0} \n\t"             \
        "bx r0 \n\t"                \
                                    \
        ".byte 0x00 \n\t"           \
        ".byte 0xBF \n\t"           \
                                    \
        ".byte 0x00 \n\t"           \
        ".byte 0xBF \n\t"           \
                                    \
        ".byte 0x00 \n\t"           \
        ".byte 0xBF \n\t" ::        \
            : "r0");
#else
#define GETPC_KILL_IDAF5_SKATEBOARD \
    __asm __volatile(               \
        "mov r0,pc \n\t"            \
        "add r0,0x10 \n\t"          \
        "push {r0} \n\t"            \
        "pop {r0} \n\t"             \
        "bx r0 \n\t"                \
        ".int 0xE1A00000 \n\t"      \
        ".int 0xE1A00000 \n\t"      \
        ".int 0xE1A00000 \n\t"      \
        ".int 0xE1A00000 \n\t" ::   \
            : "r0");
#endif
// Constant label version
#if (JUDGE_THUMB)
#define IDAF5_CONST_1_2 \
__asm __volatile( \
"b T1 \n\t" \
"T2: \n\t" \
"adds r0,1 \n\t" \
"bx r0 \n\t" \
"T1: \n\t" \
"mov r0,pc \n\t" \
"b T2 \n\t" \
:::"r0"
);
#else
#define IDAF5_CONST_1_2  \
    __asm __volatile(    \
        "b T1 \n\t"      \
        "T2: \n\t"       \
        "bx r0 \n\t"     \
        "T1: \n\t"       \
        "mov r0,pc \n\t" \
        "b T2 \n\t" ::   \
            : "r0");
#endif

// 15.  Five types of code execution time detection
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
static int _getrusage(); //Invalid
static int _clock();     //Invalid
static int _time();
static int _gettimeofday();
static int _clock_gettime();
int main()
{
    _getrusage();
    _clock();
    _time();
    _gettimeofday();
    _clock_gettime();
    return 0;
}
int _getrusage()
{
    struct rusage t1;
    /* breakpoint */
    getrusage(RUSAGE_SELF, &t1);
    long used = t1.ru_utime.tv_sec + t1.ru_stime.tv_sec;
    if (used > 2)
    {
        puts("debugged");
    }
    return 0;
}
int _clock()
{
    clock_t t1, t2;
    t1 = clock();
    /* breakpoint */
    t2 = clock();
    double used = (double)(t2 - t1) / CLOCKS_PER_SEC;
    if (used > 2)
    {
        puts("debugged");
    }
    return 0;
}
int _time()
{
    time_t t1, t2;
    time(&t1);
    /* breakpoint */
    time(&t2);
    if (t2 - t1 > 2)
    {
        puts("debugged");
    }
    return 0;
}
int _gettimeofday()
{
    struct timeval t1, t2;
    struct timezone t;
    gettimeofday(&t1, &t);
    /* breakpoint */
    gettimeofday(&t2, &t);
    if (t2.tv_sec - t1.tv_sec > 2)
    {
        puts("debugged");
    }
    return 0;
}
int _clock_gettime()
{
    struct timespec t1, t2;
    clock_gettime(CLOCK_REALTIME, &t1);
    /* breakpoint */
    clock_gettime(CLOCK_REALTIME, &t2);
    if (t2.tv_sec - t1.tv_sec > 2)
    {
        puts("debugged");
    }
    return 0;
}