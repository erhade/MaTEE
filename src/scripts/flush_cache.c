#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int flush_icache(void)
{
	int err = 0;

	asm("MOV x8, #451;"                                //x8 holds syscall no
		"SVC #0;"                                 // supervisor call
		"MOV %[result], x0" : [result] "=r" (err) //copy return code to err
		);
	return err;
}

void flush_dcache(void)
{
    // Map 32MB of memory using mmap
    void* map = mmap(NULL, 32 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Traverse the mapped memory to force page faults
    for (int i = 0; i < 32 * 1024 * 1024; i += getpagesize()) {
        volatile char* p = (volatile char*) ((char*) map + i);
        *p;
    }

    // Clean up
    if (munmap(map, 32 * 1024 * 1024) == -1) {
        perror("munmap");
        exit(1);
    }
}

int main(void)
{
	flush_dcache();
	flush_icache();
}
