
#include <osv/osv_c_wrappers.h>
#include <osv/debug.hh>
#include <osv/sched.hh>
#include <osv/app.hh>
#include <malloc.h>

using namespace osv;
using namespace sched;

int osv_get_all_app_threads(pid_t tid, pid_t** tid_arr, size_t *len) {
    thread* app_thread = tid==0? thread::current(): thread::find_by_id(tid);
    if (app_thread == nullptr) {
        return ESRCH;
    }
    std::vector<thread*> app_threads;
    with_all_app_threads([&](thread& th2) {
        app_threads.push_back(&th2);
    }, *app_thread);

    *tid_arr = (pid_t*)malloc(app_threads.size()*sizeof(pid_t));
    if (*tid_arr == nullptr) {
        *len = 0;
        return ENOMEM;
    }
    *len = 0;
    for (auto th : app_threads) {
        (*tid_arr)[(*len)++] = th->id();
    }

#if 1
    size_t ii;
    char *str1 = (char*)malloc(1024*4);
    char *str2 = str1;
    str2 += snprintf(str2, 1024*4 - (str2-str1), "TTRT APP_ALL_THREADS %d -> [", tid);
    for (ii=0; ii<*len; ii++) {
        str2 += snprintf(str2, 1024*4 - (str2-str1), "%d ", (*tid_arr)[ii]);
    }
    str2 += snprintf(str2, 1024*4 - (str2-str1), "]\n");
    fprintf(stderr, "%s", str1);
    free(str1);
#endif
    return 0;
}
