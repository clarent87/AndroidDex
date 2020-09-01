#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h> 

/*
* build command >> ndk-build -B APP_ABI=all APP_PLATFORM=android-23
* 권한은 root 필요할듯.
*/

/**
 * Utils
 */
#define MAX_BUFF_LEN     1024
#define MAX_SEGMENT_SIZE 5120

typedef unsigned long ulong;

typedef struct segment {
    ulong start;
    ulong end;
    char module_name[MAX_BUFF_LEN];
} segment;

void str_tolower(char *str)
{
    int i;
    for (i = 0; i < strlen(str); i++) {
        str[i] = (char) tolower(str[i]);
    }
}

// parse the maps
int read_maps(pid_t pid, segment *segments, int *segment_size);

// save dump to file
int save_to_file(void* dump, size_t size, char *output_name); // dump는 char array주소.

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: %s <pid> <library> <output>\n", argv[0]);
        printf("  <pid> - PID of process to target\n");
        printf("  <library> - library name to target\n");
        printf("  <output> - output file name\n");
        return -1;
    }

    // PARSE CLI ARGS
    pid_t pid = strtol(argv[1], NULL, 10);
    printf(" * Launching with a target PID of: %zd\n", pid);
    
    char module[MAX_BUFF_LEN] = "";
    strncpy(module, argv[2], strlen(argv[2]));
    printf(" * Launching with a target library of: %s\n", module);

    char output[MAX_BUFF_LEN] = "";
    strncpy(output, argv[3], strlen(argv[3]));
    printf(" * Launching with a target output of: %s\n", output);

    ulong start; // library start address
    ulong end;   // library end address
    ulong size;  // library size

    // READ THE MAPS
    segment *segments = malloc(sizeof(segment) * MAX_SEGMENT_SIZE);
    int segment_size = 0;
    int res_code = 0;
    res_code = read_maps(pid, segments, &segment_size);
    if(res_code != 0){
        printf("[-] Read segment information failed\n");
        free(segments);
        return -1;
    }
    printf("[+] Read segment information success, size: %d\n", segment_size);


    // GET library start/end address
    int i = 0;
    int has_module = 0;
    for(i=0; i<segment_size; i++){ // while 돌면서 찾긴하네.. 근데 예상대로 이름으로는 가장 처음 만난것을 선택함.. 
        if(strstr(segments[i].module_name, module) != NULL){
            start = segments[i].start;
            end = segments[i].end;
            has_module = 1;
            printf("[+] Target segment information: {start:0x%lx, end:0x%lx, name:%s}\n", start, end, module);
            break;
        }
    }
    if(has_module == 0){ // library가 maps 상에 없는경우
        printf("[-] Check input module name: %s\n", module);
        return -1;
    }

    // Build iovec structs
    size = end - start;

    struct iovec local[1];
    local[0].iov_base = calloc(size, sizeof(char));
    local[0].iov_len = size;

    struct iovec remote[1];
    remote[0].iov_base = (void*)start;
    remote[0].iov_len = size;

    // Call process_vm_readv - handle any error codes
    ssize_t nread = process_vm_readv(pid, local, 1, remote, 1, 0); //array size니까 1이어야지. 
    if (nread < 0) {
        switch (errno) {
            case EINVAL:
              printf("ERROR: INVALID ARGUMENTS.\n");
              break;
            case EFAULT:
              printf("ERROR: UNABLE TO ACCESS TARGET MEMORY ADDRESS.\n");
              break;
            case ENOMEM:
              printf("ERROR: UNABLE TO ALLOCATE MEMORY.\n");
              break;
            case EPERM:
              printf("ERROR: INSUFFICIENT PRIVILEGES TO TARGET PROCESS.\n");
              break;
            case ESRCH:
              printf("ERROR: PROCESS DOES NOT EXIST.\n");
              break;
            default:
              printf("ERROR: AN UNKNOWN ERROR HAS OCCURRED.\n");
        }

        return -1;
    }

    printf(" * Executed process_vm_ready, read %zd bytes.\n", nread);
    //printf("%s\n", local[0].iov_base);// 밖에다 뿌리네.. 일단 test
    if(save_to_file(local[0].iov_base,remote[0].iov_len,output));
    else 
      printf(" * save_to_file Done\n");
    
    free(segments);
    return 0;
}

int read_maps(pid_t pid, segment *segments, int *segment_size)
{
    // maps 파일 열기
    char maps_path[MAX_BUFF_LEN];
    sprintf(maps_path, "/proc/%d/maps", pid);
    FILE *maps_handle = fopen(maps_path, "r");
    if (maps_handle == NULL) {
        printf("[-] Open %s failed: %d, %s\n", maps_path, errno, strerror(errno));
        return -1;
    }

    int index = 0;
    ulong start, end; 
    char line[MAX_BUFF_LEN];
    char module_name[MAX_BUFF_LEN]; 
    char pre_module_name[MAX_BUFF_LEN]; 
    while (fgets(line, MAX_BUFF_LEN, maps_handle) != NULL) { 
        memset(module_name, 0, MAX_BUFF_LEN);
        // printf("[*] Content: %s", line);
        int rv = sscanf(line, "%lx-%lx %*s %*s %*s %*s %s", &start, &end, module_name);
        // printf("[*] Segment information:{start:0x%lx, end:0x%lx, name:%s}\n", start, end, module_name);
        if (rv != 3) {
            //printf("[-] Scanf failed: %d, %s\n", errno, strerror(errno));
            continue;
        } else { 
            str_tolower(module_name);
            if (strcmp(pre_module_name, module_name) == 0) {
                if (segments[index - 1].end < end) {
                    segments[index - 1].end = end;
                }
            } else {
                strcpy(pre_module_name, module_name);
                strcpy(segments[index].module_name, module_name);
                segments[index].start = start;
                segments[index].end = end;
                index++;
            }
        }
    }
    *segment_size = index;
    fclose(maps_handle);
    maps_handle = NULL;
    return 0;
}

int save_to_file(void* dump, size_t size, char *output_name){
  int res_code = 0;
  FILE *output_handle = fopen(output_name, "wb");
  if (fwrite(dump, sizeof(char), size, output_handle) == size) {
      res_code = 0;
  } else {
      printf("[-] Write %s failed: %d, %s\n", output_name, errno, strerror(errno));
      res_code = -1;
  }
  fclose(output_handle);
  return res_code;
}
