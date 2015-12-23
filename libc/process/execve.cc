#include <unistd.h>
#include <osv/stubbing.hh>
#include "../libc.hh"
#include "osv/run.hh"

int execve(const char *path, char *const argv[], char *const envp[])
{
    WARN_STUBBED();
    return libc_error(ENOEXEC);
}
