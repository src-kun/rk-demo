#ifndef SYSCALLS_H
#define SYSCALLS_H

extern int errno;

#define my__syscall_return(type, res) \
do { \
    if ((unsigned long)(res) >= (unsigned long)(-(128 + 1))) { \
        errno = -(res); \
        res = -1; \
    } \
    return (type) (res); \
} while (0)

#define my_syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("push %%ebx ; movl %2,%%ebx ; int $0x80 ; pop %%ebx" \
    : "=a" (__res) \
    : "0" (__NR_##name),"ri" ((long)(arg1)),"c" ((long)(arg2)) \
    : "memory"); \
my__syscall_return(type,__res); \
}


#endif
