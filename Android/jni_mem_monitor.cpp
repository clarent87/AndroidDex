//
// Created by alien on 2020-09-17.
//

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <cstring>
#include <pthread.h>
#include <poll.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <sys/types.h>
#include "logger.h"
#include "monitor.h"

static int tids[1024];
static int tids_size;
/*
 * save all tids to global array(tids)
 * return :  total size of tids or 0 if error occured
 */
static int getAllTids()
{
    DIR *dir;
    int i;
    struct dirent *entry;
    pid_t tid;

    dir = opendir("/proc/self/task");
    if (dir == NULL) return 0;

    i = 0;
    while((entry = readdir(dir)) != NULL) {
        tid = atoi(entry->d_name);
        if (tid != 0 ) { // d_name이 0으로 찍히면 directory ., .. 인듯.
            LOGD("[*] get tid: %d",tid);
            tids[i++] = tid;
        }
    }
    closedir(dir);
    return i;
}

// make wd array
// caller should handle wd array ( i.e free array )
// fd : is inotify fd
// add_watch 실패시 wd에 -1넣은채로 그냥 진행
// 문자열 난독화는 필요.
static int* add_watch_all(int fd){
    int *wd, pid;
    char maps_path[32];
    char mem_path[32];
    char task_maps_path[32];
    char task_mem_path[32];

    pid = getpid();

    // 1. get all tids
    tids_size = getAllTids();
    // 2. allocate memory for wd
    wd = static_cast<int *>(calloc(tids_size*4, sizeof(int))); // maps, mem

    // 3. while
    for(int i=0; i<tids_size; i++){
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", tids[i]);
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", tids[i]);
        snprintf(task_maps_path, sizeof(maps_path), "/proc/self/task/%d/maps", tids[i]);
        snprintf(task_mem_path, sizeof(mem_path), "/proc/self/task/%d/mem", tids[i]);
        LOGD("[*] watch : %s", maps_path);
        LOGD("[*] watch : %s", mem_path);
        LOGD("[*] watch : %s", task_maps_path);
        LOGD("[*] watch : %s", task_mem_path);

        wd[i*4] = inotify_add_watch(fd, maps_path,IN_OPEN | IN_ACCESS);
        if ( wd[i*4] == -1 ) {
            LOGE("[*] Cannot watch '%s': %s\n", maps_path, strerror(errno));
        }

        wd[i*4+1] = inotify_add_watch(fd, mem_path,IN_OPEN | IN_ACCESS);
        if (  wd[i*4+1] == -1 ) {
            LOGE("[*] Cannot watch '%s': %s\n", mem_path, strerror(errno));
        }
        wd[i*4+2] = inotify_add_watch(fd, mem_path,IN_OPEN | IN_ACCESS);
        if (  wd[i*4+1] == -1 ) {
            LOGE("[*] Cannot watch '%s': %s\n", mem_path, strerror(errno));
        }
        wd[i*4+3] = inotify_add_watch(fd, mem_path,IN_OPEN | IN_ACCESS);
        if (  wd[i*4+1] == -1 ) {
            LOGE("[*] Cannot watch '%s': %s\n", mem_path, strerror(errno));
        }
    }
    return wd;
}

/**
 * event log 찍고 kill process 진행
 * @param fd inotify fd
 * @param wd wd array
 */
static void handle_event(int fd , int *wd){
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    char *ptr;

    LOGD("[*] in handle_event");

    // todo :무한 loop 진행 ( 뭐 그럴 필요 없어 보이긴 하지만.. ) => 하나라도 걸리면 kill 하기 때문..
    // todo: 이부분도 원하는 event가 아닌경우 때문에 while하는듯.. 그러면 여기선 whild안해도 될듯한데.. ( 이위에 while있으니.. ) => 혹시 read 의 buf가 너무많아서 분할해서 읽기 때문?
    while(1){
        // 1) read event
        len = read(fd, buf, sizeof buf);
        if (len == -1 && errno != EAGAIN) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        // 2) non-block read일때 => while의 종료 조건으로 활용
        if (len <= 0) break;

        // 3) for
        for(ptr = buf; ptr < buf +len; ptr += sizeof(struct inotify_event) + event->len){ // inotify struct가 name field때문에 가변.
            event = (const struct inotify_event *) ptr;

#if !NDEBUG
            // 4) logging용 code
            if (event->mask & IN_OPEN)
                LOGD("IN_OPEN: ");
            if (event->mask & IN_CLOSE_NOWRITE)
                LOGD("IN_CLOSE_NOWRITE: ");
            if (event->mask & IN_CLOSE_WRITE)
                LOGD("IN_CLOSE_WRITE: ");

            /* Print the name of the watched directory */
            for (int i = 0; i < tids_size*4; i++)
            {
                if (wd[i] == event->wd )
                {
                    if( i%4 == 0  ) LOGD("/proc/%d/maps", tids[i/4]);
                    else if( i%4 == 1 ) LOGD("/proc/%d/mem", tids[i/4]);
                    else if (i%4 == 2) LOGD("/proc/self/task/%d/maps", tids[i/4]);
                    else LOGD("/proc/self/task/%d/mem", tids[i/4]);
                    break;
                }
            }
#endif
            kill(getpid(),SIGKILL); // process id 받아서 강제 kill ( 아 fork가 resource 문제 있댔지.. kill 말고. )
        }
    }
    return;
}

/**
 * - thread consumer 형태로 치환.
 * - todo : signal handler 등록해 줘야함 ( 근데 해당 시그널을 다른데서 처리하면 어쪄지? thread zombie 처리는 어떻게 하지? 일단 test용이니까 걍진행?)
 * - todo : poll의 무한 loop 필요한가 고려해야함. => 아마 POLLIN이 아닌 이벤트 발생 때문일듯한데..
 */
void* monitor(void*){
    int fd, i, poll_num;
    nfds_t nfds = 1;      // fd 하나만 볼것.
    struct pollfd fds[1]; // fd 하나만 볼것.
    int *wd;

    // 1) inotify fd 생성
    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1)
    {
        perror("[*] inotify_init1");
        exit(EXIT_FAILURE); // thread 다시 호출 가능하게.. 해야할듯.. 구조상 타 쓰레드에서 join 대기..??
    }
    LOGD("[*] make inotify fd\n");

    // 2) watch
    wd = add_watch_all(fd);
    LOGD("[*] add watch");

    // 4) prepare poll
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    LOGD("[*] Listening for events.\n");

    // 5) loop poll ( 사실 무한 루프 필요한가 싶다.. poll이 block이라.. )
    while (1)
    {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1)
        {
            if (errno == EINTR) continue;
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0)
        {
            LOGD("[*] get poll event\n");
            if (fds[0].revents & POLLIN) handle_event(fd, wd);
        }
    }
    printf("Listening for events stopped.\n");
    return 0;
}

void mem_monitor(){
    int status;
    pthread_t test;
    pthread_attr_t attrib;

    pthread_attr_init(&attrib);
    pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_DETACHED); // join 필요 없게..

    pthread_create(&test,&attrib,monitor,(void*)NULL);
    pthread_setname_np(test, "mem-monitor");
    LOGD("[*] mem-monitor is created");

}
// TODO 시그널 핸들러에서 아래 내용 진행해야 함. ( 시그널 핸들러에서 정리? )
// TODO 근데 debugger에 의한 정지는 어떻하기?
///* Close inotify file descriptor */
// close(fd);
// path malloc 내용 free
//exit(EXIT_SUCCESS);
