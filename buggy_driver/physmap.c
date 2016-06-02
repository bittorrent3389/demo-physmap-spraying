/* After rebooting, need to 
 * mknod /dev/demo c 60 0
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jeremy Huang");
unsigned long *kaddr;
ssize_t (*shellcode)(void);
static char gg2[] = 
	"\x55"							/* push %rbp */
	"\x48\x89\xe5"					/* mov %rsp,%rbp */
	"\x53"							/* push %rbx */
	"\x48\xc7\xc3\x90\x83\x08\x81"  /* mov $0xffffffff81088390,%rbx */
	"\x48\xc7\xc1\x70\x86\x08\x81"	/* mov $0xffffffff81088670,%rcx */
	"\x48\x31\xff"					/* xor %rdi,%rdi */
	"\xff\xd1"						/* callq *%rcx */
	"\x48\x89\xc7"					/* xor %rax, %rax ; %rax : reture value */
	"\xff\xd3"						/* pop %rbx	*/
	"\x48\x31\xc0"					/* leaveq */
	"\x5b\xc9\xc3";					/* req */
static ssize_t drv_read(struct file *file, char *buf, size_t count, loff_t *ppos) {
	printk("Reading...\n");
	return count;
}
static ssize_t drv_write(struct file *file, const unsigned long *buff,
		size_t len, loff_t *off) {
	int ra;
	printk("Writing...\n");
	kaddr = (void *) *buff;
	printk("kaddr : %lx\n",(unsigned long) kaddr);
	printk("machine code : %lx\n", (unsigned long) *kaddr);
	shellcode = kaddr;
	if ((ra = shellcode()) != 0) {
		printk("shellcode return value : %d\n", ra);
		printk("shellcode is done successfully.\n");
	}
	return len;	
}
struct file_operations drv_fops = {
	    .read = drv_read,
		.write = drv_write
};
static int __init physmap_init(void) {

	if ( register_chrdev(60, "demo", &drv_fops) <0 ) {
		printk("can't register\n");
		return (-EBUSY);
	}  
    printk("Started!!! buggy driver...\n");
	//shellcode = gg2;
	//shellcode();
	//printk("gg is done.\n");
	return 0;
}
static void __exit physmap_exit(void) {
   unregister_chrdev(60, "demo");
   printk(KERN_ALERT "Goodbye, world \n");
}

module_init(physmap_init);
module_exit(physmap_exit);

