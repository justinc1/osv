#include <unistd.h>
#include <osv/stubbing.hh>
#include "../libc.hh"
#include "osv/run.hh"

int execve(const char *path, char *const argv[], char *const envp[])
{
    // will start app at path in new OSv thread, without replacing current binary.
    return osv_run_app_in_namespace(path, argv, envp);
    /* WARN_STUBBED();
    return libc_error(ENOEXEC); */
}
