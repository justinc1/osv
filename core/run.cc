#include <osv/run.hh>
#include <thread>

namespace osv {

std::shared_ptr<osv::application> run(std::string path,
                     std::vector<std::string> args,
                     int* return_code,
                     bool new_program,
                     const std::unordered_map<std::string, std::string> *env)
{
    auto app = osv::application::run(path, args, new_program, env);
    app->join();
    if (return_code) {
        *return_code = app->get_return_code();
    }
    return app;
}

std::shared_ptr<osv::application> run(std::string path,
                                 int argc, char** argv, int *return_code)
{
    std::vector<std::string> args;
    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }
    return run(path, args, return_code);
}

}

typedef struct thread_status {
    long tid;
    long exit_code;
} thread_status;

std::vector<std::shared_ptr<osv::application>> exec_apps;
std::vector<std::thread> exec_threads;
/* Record thread state changes (termination) by pushing new info to array.
 * It is used to implement waitpid like functionality for threads (osv_waittid).
 **/
std::vector<thread_status> exec_thread_status;
mutex exec_mutex;

int osv_thread_run_app_in_namespace(const char *filename,
                                    const std::vector<std::string> *args,
                                    std::unordered_map<std::string, std::string> *envp,
                                    long* thread_id,
                                    int notification_fd)
{
    std::shared_ptr<osv::application> app;
    int ret;
    bool new_program = true; // run in new ELF namespace
    /* same value as returned by gettid() syscall. */
    long tid = sched::thread::current()->id();

    fprintf(stderr, "osv_thread_run_app_in_namespace... tid=%ld\n", tid);
    if(thread_id) {
        *thread_id = tid;
    }

    // no new thread created by osv::run (I think) and caller is blocked
    app = osv::run(filename, *args, &ret, new_program, envp);
    exec_apps.push_back(app);
    fprintf(stderr, "osv_thread_run_app_in_namespace ret = %d tid=%ld\n", ret, tid);
    // free data allocated in osv_run_app_in_namespace
    delete args;
    delete envp;
    fprintf(stderr, "osv_thread_run_app_in_namespace... tid=%ld DONE\n", tid);
    thread_status th_status = {tid, ret};

    /* Check that exec_mutex is in the same ELF namespace */
    fprintf(stderr, "osv_thread_run_app_in_namespace &exec_mutex=%p\n", &exec_mutex);
    WITH_LOCK(exec_mutex) {
        exec_thread_status.push_back(th_status);
    }

    // remove current thread from exec_threads ?
    // Trigger event notification via file descriptor (fd created with eventfd).
    if(notification_fd > 0) {
        long long notif = 1;
        write(notification_fd, &notif, sizeof(notif));
    }
    return ret;
}

/*
 * Run filename in new thread, with its own memory (ELF namespace).
 * New thread ID is returned in thread_id.
 * On thread termination, event is triggered on notification_fd.
 **/
int osv_run_app_in_namespace(const char *filename,
                             char *const argv[],
                             char *const envp[],
                             long* thread_id,
                             int notification_fd)
{
    fprintf(stderr, "osv_run_app_in_namespace... \n");
    std::thread app_thread;
    if(thread_id) {
        *thread_id = 0;
    }

    /*
     * We have to start new program in new thread, otherwise current thread 
     * waits until new program finishes.
     * 
     * Caller might change memory at argv and envp, before new thread has chance
     * to use/copy the argv/envp data. Make a copy of that data, _before_ running
     * new thread. Making a copy inside the thread - in 
     * osv_thread_run_app_in_namespace - is to late.
     * 
     * Args and envp are used in to-be-started thread, so they should not be on
     * stack. Malloc them here, and free them in thread.
     **/
    std::vector<std::string> *args;
    args = new std::vector<std::string>;
    if(args == NULL) {
        return -ENOMEM;
    }
    char * const *cur_arg;
    for(cur_arg = argv; cur_arg != NULL && *cur_arg != NULL && **cur_arg != '\0'; cur_arg++ ) {
        //fprintf(stderr, "cur_arg = %p  %p  %s\n", cur_arg, *cur_arg, *cur_arg);
        fprintf(stderr, "cur_arg = %s\n", *cur_arg);
        args->push_back(*cur_arg);
    }
    
    char * const *env_kv;
    char key[1024], *value;
    std::unordered_map<std::string, std::string> *envp_map;
    envp_map = new std::unordered_map<std::string, std::string>;
    if(envp_map == NULL) {
        return -ENOMEM;
    }
    for(env_kv = envp; env_kv != NULL && *env_kv != NULL && **env_kv != '\0'; env_kv++ ) {
        //fprintf(stderr, "env_kv = %s\n", *env_kv);
        strncpy(key, *env_kv, 1024);
        value = strstr(key, "=");
        if(value == NULL) {
            fprintf(stderr, "ENVIRON ignoring ill-formated variable %s (not key=value)\n", key);
            continue;
        }
        value[0] = '\0'; // terminate key
        value++;
        //fprintf(stderr, "  k=v %s = %s\n", key, value);
        (*envp_map)[key] = value;
    }
    
    exec_threads.push_back(std::thread(osv_thread_run_app_in_namespace, filename, args, envp_map, thread_id, notification_fd));
    
    fprintf(stderr, "osv_run_app_in_namespace... DONE\n");
    return 0;
}

extern "C" {

long osv_execve(const char *path, char *const argv[], char *const envp[], 
    long *thread_id, int notification_fd)
{
    // will start app at path in new OSv thread, without replacing current binary.

    fprintf(stderr, "OSv osv_execve:%d path=%s argv=%p envp=%p thread_id=%p %d notification_fd=%d\n",
        __LINE__, path, argv, envp, thread_id, *thread_id, notification_fd);
    fprintf(stderr, "OSv osv_execve:%d   argv[0]=%p %s\n", __LINE__, argv, argv[0]);
    fprintf(stderr, "OSv osv_execve:%d   envp[0]=%p %s\n", __LINE__, envp, envp[0]);
    return (long) osv_run_app_in_namespace(path, argv, envp, thread_id, notification_fd);
}

long osv_waittid(long tid, int *status, int options) {
    
    //fprintf(stderr, "TTRT osv_waittid tid=%ld options=%d (WNOHANG=%d) th_status_size=%d\n",
    //    tid, options, WNOHANG, exec_thread_status.size());
    while(exec_thread_status.empty()) {
        if(options & WNOHANG) {
            return 0;
        }
        // else block
        usleep(1000*100); // barrier
        // could become inf loop
    }
    
    // TODO mutex
    thread_status th_status;
    /* Check that exec_mutex is in the same ELF namespace */
    fprintf(stderr, "osv_waittid &exec_mutex=%p DONE\n", &exec_mutex);
    WITH_LOCK(exec_mutex) {
        th_status = exec_thread_status.back();
        exec_thread_status.pop_back();
    }
    fprintf(stderr, "TTRT osv_waittid th_status .tid=%ld .exit_code=%d\n",
        th_status.tid, th_status.exit_code);
    if(status) {
        *status = ((th_status.exit_code<<8) & 0x0000FF00);
    }
    return th_status.tid;
}

};