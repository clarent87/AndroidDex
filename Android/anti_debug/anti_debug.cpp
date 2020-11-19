#include "anti-debug.h"
#include "logger.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <pthread.h>
#include <cstring>
#include <fcntl.h>
#include <sys/wait.h>

//ref. https://bbs.pediy.com/thread-223324.htm
//ref. https://www.programmersought.com/article/1472621633/

int pipefd[2];
int g_child_pid;

void anti_ptrace(){
    ptrace(PTRACE_TRACEME, 0, 0, 0); // 이건 main에선 안먹힘.
}

/* 차리리 child가 죽거나 멈췄을때 signal 받아서 처리하는게 좋을거 같음*/
/* while에서 까딱잘못하면 read에 값이 없어서 current_tracerpid 가 -1이 뜨면서 죽음.. */
/* 그렇다고 block으로 동작시킬수도 없고.. */
/* 요는 child가 죽지 않았음을 보장해야하는거.. */
/* -1 카운트를 세는 코드를 넣으면 쫌 나을수도.. */
void* ThreadConsumer(void*){
    /* this is FOR main process */
    /* 시그널 예외 필요할듯.. */
    /* main thread에서 버튼 처리 할때 -1 뜨면서 죽음. */
    int current_tracerpid = -1;

    /* 1) init pipe */
    close(pipefd[1]);  // 이부분 문제임.. 코드상 thread를 생성하고 fork하는데
                       //이때 thread에서 pipe close까지 진행하고 fork 가는경우 당연히 file이 닫혀서 eof 가 읽히는 듯.
    sleep(4);
    read(pipefd[0], &current_tracerpid, 4);


    LOGI("[*](in thread) init tracerpid is %d", current_tracerpid);

    /* 2) set non-block */
    fcntl(pipefd[0],F_SETFL ,O_NONBLOCK ); // non-block으로 진행 ( write 대기 안함 )

    /* 3) while */
    // app life-cycle 전체에서 살아있어야 함. ( background로 빠질땐 thread stop하나? 상태 변화 check? 프로세스는 waitpid로 가능한거 같은데. )
    // 아.. ptrace attach는 thread별로 니까. 프로세스에 걸어도(중지됨), 현재 thread는 동작 할듯.
    // dump 스피드가 빠르지 않고.. 적당히 context switching이 된다면 dump 방지가 되긴 하겠네..
    while(true){
        read(pipefd[0], &current_tracerpid, 4); //여기서 지속적으로 0이 와야함.
        sleep(1); // 일단 log 때문에 넣음 나중엔 제거해야함.
        LOGI("[*](in thread) tracerpid is %d", current_tracerpid);

        if(current_tracerpid !=0){
            kill(g_child_pid,SIGKILL);
            kill(getpid(),SIGKILL);
        }
        current_tracerpid = -1; // child가 죽을껄 대비 한듯.. pipe로 0이 안오면 죽음.
    }
}

void anti_debugging(){
    pid_t parent_pid,child_pid;
    char status_file_name[PATH_MAX];
    char line[PATH_MAX];
    pthread_t thr;
    pthread_attr_t attrib;
    FILE *fd;

    /* 1) prepare */
    parent_pid = getpid();
    pipe(pipefd); // pipe는 fork 후 close가 정석 근데 ref에서는 잘못된게 아닌가 싶네..
    sprintf(status_file_name, "/proc/%d/status",parent_pid);

    /* 2) make thread 
    *     - 예외처리는 일단 생략
    *     - 지금 thread 생성 위치 잘못됨,, 이경우 fork 전에 thread 생성 => close pipe => read eof 순으로 진행.. 종료..  
    */
    pthread_attr_init(&attrib);
    pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_DETACHED);
    pthread_create(&thr,&attrib,ThreadConsumer,(void*)NULL);
    pthread_setname_np(thr, "ThreadConsumer");

    /* 3) fork */
    // 기본적으로 멀티쓰레드 환경에서 fork는 위험
    // 자식 process는 fork한 process 제외 복사된 모든 쓰레드를 kill 한다함.. 자원 회수 안됨.
    child_pid=fork();
    if(child_pid==0){
        /* in child */
        close(pipefd[0]); // 읽기 pipe는 필요 없음
        ptrace(PTRACE_TRACEME, 0, 0, 0); // 실패 여지 있나? => 쓰던안쓰던 어쨋든 스레드에서는 -1이 되서 죽음.

        while(true){
            /* parent 의 TracerPID 감시 */
            fd = fopen(status_file_name,"r");
            while(fgets(line, PATH_MAX, fd)){ // 위치 direct로 갈순 없나?
                if(strstr(line, "TracerPid") != NULL){
                    int status = atoi(&line[10]); // "TracerPID: "
                    LOGI("[*](in child) tracer pid:%d", status);
                    write(pipefd[1],&status ,4); // block으로 동작 즉, read에서 다 읽을 때까지 기다림
                    fclose(fd); // 일단 한번 확인후.. 종료
                    if(status !=0) return; // tracing 중이면 child는 return. ( exit 해도 될거 같긴한데. )
                    break;
                }
            }
            sleep(1);
        }

    }else{
        /* in parent */
        g_child_pid = child_pid;
    }
}
/////////////////////////////////////////////////////////////////////////////
/*
 * 이거 child kill일때만 반응하고
 * tracing 때문에 sigstop날아온건 반응을 못하는듯. ( debuger로 상태변화가 오나봄.. )
*/
void *MonitorPidThreadFunc(void *) {
    int status;
    waitpid(g_child_pid, &status, 0);
    // child status should never change

    LOGD("[*] anti_debug, monitor_pid(), status: %d", status);

    _exit(0);
}

void anti_debugging2(){
    /* 1) child가 parent에 attach한 상태에서*/
    /* 2) parent에 signal handler를 두는 구현안.*/
    g_child_pid = fork();
    if (g_child_pid == 0) {
        int parent_pid = getppid();
        int status;

        LOGD("anti_debug, child process");
        if (ptrace(PTRACE_ATTACH, parent_pid, NULL, NULL) == 0) {
            LOGD("anti_debug, child process attach success");
            waitpid(parent_pid, &status, 0);
            ptrace(PTRACE_CONT, parent_pid, NULL, NULL);
            while (waitpid(parent_pid, &status, 0)) { // 와우.. parent의 waitpid도 가능하네.. debugger라 가능한가?
                if (WIFSTOPPED(status)) { // 이런상황이 있지도 않을거 같음.. signal이 먹히지도 않음.. ( 아마 signal을 tracer가 받을듯.. default는 무시 아닐까?)
                    ptrace(PTRACE_CONT, parent_pid, NULL, NULL);
                } else {
                    // process has exited
                    LOGD("anti_debug: process has exited, status: %d", status);
                    _exit(0);
                }
                LOGD("anti_debug: process has status: %d", status);
            }
        }
        LOGD("anti_debug, child process attach failed");
    } else {
        if (g_child_pid > 0) {
            pthread_t t;
            // start monitoring thread
            pthread_create(&t, NULL, MonitorPidThreadFunc, (void *) NULL);
            LOGD("anti_debug, thread created(monitor_pid)");
        }
    }
}


///////////////////////////////////////////////////////////////////////////////
void* test_consumer(void*){
    sleep(20);
    LOGD("(*) this is thread test");
    return NULL;
}
void thread_test(){
    // thread 생성 함수 등의 return으로 error handling해줘야함.
    // 어짜피 app이 죽으면 thread고 뭐고 다 날아가네..
    int status;
    pthread_t test;
    pthread_attr_t attrib;

    pthread_attr_init(&attrib);
    pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_DETACHED);

    pthread_create(&test,&attrib,test_consumer,(void*)NULL);
    pthread_setname_np(test, "test");
    LOGD("(*) test status is %d",status);
}
