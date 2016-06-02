#define PAGE_OFFSET 0xffff880000000000UL    /* kernel space */
#define KERN_LOW    PAGE_OFFSET     /* range start */
#define KERN_HIGH   0xffff880080000000UL    /* range end */
#define ARRAY_SIZE(a)       (sizeof (a) / sizeof (*(a)))
#define KERNEL_START    PAGE_OFFSET

typedef unsigned int __u32,u32; 
struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

struct thread_info {
	// for openSuse 42.1 Leap
	struct task_struct  *task;      /* main task structure */
    __u32           flags;      /* low level flags */
    __u32           status;     /* thread synchronous flags */
    __u32           cpu;        /* current CPU */
    int         saved_preempt_count;
    unsigned long   addr_limit;
 
	/* ... */
};

typedef struct kernel_cap_struct {
    __u32 cap[2];
} kernel_cap_t;

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

struct cred {
	// for openSuse 42.1 Leap
    int usage; // atomic_t usage;
	void *put_addr;
	unsigned magic;	
    uid_t uid;
    gid_t gid;
    uid_t suid;
    gid_t sgid;
    uid_t euid;
    gid_t egid;
    uid_t fsuid;
    gid_t fsgid;
    unsigned securebits;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;

    unsigned char jit_keyring;
	void *session_keyring;
	void *process_keyring;
    void *thread_keyring;
    void *request_key_auth;
    struct task_security_struct *security;
	
    /* ... */
};

struct task_security_struct {
    u32 osid;
    u32 sid;
    u32 exec_sid;
    u32 create_sid;
    u32 keycreate_sid;
    u32 sockcreate_sid;
};

struct task_struct_partial {
    struct list_head cpu_timers[3];
    struct cred *real_cred;
    struct cred *cred;
    //struct cred *replacement_session_keyring;
    char comm[16];
};
