//
// Created by alien on 2020-09-17.
//

#ifndef MY_APPLICATION_MONITOR_H
#define MY_APPLICATION_MONITOR_H

#define PATH_LEN 2

void mem_monitor();
char* g_path[] = {"/proc/self/maps","/proc/self/mem"};


#endif //MY_APPLICATION_MONITOR_H
