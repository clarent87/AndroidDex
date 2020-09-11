#include <stdlib.h>
#include <stdio.h>
#include <sys/inotify.h>
int keep_running=1;
void signal_handler(int signum){
	keep_running =0;
}

int open_inotify_fd(){
	int fd=inotify_init();
	if(fd<0){
		printf("error in inotify_init()");
	}
	return fd;
}

int watch_dir(int fd,const char *dirname,unsigned long mask){
	int wd=inotify_add_watch(fd,dirname,mask);
	if(wd<0){
		printf("Cannot add watch for \"%s\" with event mask %lX",dirname,mask);
		fflush(stdout);
	}else{
		printf("Watching %s WD=%d\n",dirname,wd);
	}
	return wd;
}

int process_inotify_events(queue_t q,int fd){
	while(keep_running ){
		if(event_check(fd)>0){
			int r;
			r=read_events(q,fd);
			if(r<0){
				break;
			}else{
				handle_events(q);
			}
		}
	}
	return 0;
}


int event_check(int fd){
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(fd,&rfds);
	return select(FD_SETSIZE,&rfds,NULL,NULL,NULL);
}

int read_events(queue_t q,int fd){
	char buffer[16384];
	size_t buffer_i;
	struct inotify_event *pevent;
	queue_entry_t event;
	ssize_t r;
	size_t event_size, q_event_size;
	int count=0;

	r=read(fd,buffer,16384);
	if(r<=0){
		return r;
	}
	buffer_i=0;
	while(buffer_i<r){
		pevent=(struct inotify_event *)&buffer[buffer_i];
		event_size=offsetof(struct inotify_event,name)+pevent->len;
		q_event_size=offsetof(struct queue_entry,inot_ev.name)+pevent->len;
		event=malloc(q_event_size);
		memmove(&(event->inot_ev),pevent,event_size);
		queue_enqueue(event,q);
		buffer_i+=event_size;
		count++;
	}
	printf("\n%d events queued\n",count);
	return count;
}

void handle_event(queue_entry_t event){
	if(event->inot_ev & IN_ALL_EVENTS){
		// rsync src dst...
	}
}
//Pattern: ./inotify src dst &
int main(int argc, char **argv){
	int inotify_fd;
	inotify_fd=open_inotify_fd();
	if(signal(SIGINT,signal_handler)==SIG_IGN){
		signal(SIGINT,SIG_IGN);
	}
	if(inotify_fd>0){
		queue_t q;
		q=queue_create(128);
		int wd=0;
		int index;
		printf("\n");
		for(index=1;index<argc && wd>=0;index++){
			wd= watch_dir(inotify_fd,argv[indedx],IN_ALL_EVENTS);
		}
		if(wd>0){
			process_inotify_events(q,inotify_fd);
		}
		printf("\nTerminating\n");
		close_inotify_fd(inotify_fd);
		queue_destroy(q);
	}
	return 0;
}
