#include <osv/run.hh>
#include <thread>

namespace osv {

std::shared_ptr<osv::application> run(std::string path,
                                 std::vector<std::string> args,
                                 int* return_code,
                                 bool new_program)
{
    auto app = osv::application::run(path, args, new_program);
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

std::vector<std::shared_ptr<osv::application>> exec_apps;
std::vector<std::thread> exec_threads;

int osv_thread_run_app_in_namespace(const char *filename,
                                    char *const argv[],
                                    char *const envp[],
                                    int env_mod_delay)
{
    std::vector<std::string> args;
    std::shared_ptr<osv::application> app;
    int ret;

    fprintf(stderr, "osv_thread_run_app_in_namespace... \n");
    fprintf(stderr, "osv_thread_run_app_in_namespace sleep %d sec\n", env_mod_delay);
    std::this_thread::sleep_for(std::chrono::seconds(env_mod_delay));

    char * const *cur_arg;
    for(cur_arg = argv; cur_arg != NULL && *cur_arg != NULL && **cur_arg != '\0'; cur_arg++ ) {
        //fprintf(stderr, "cur_arg = %p  %p  %s\n", cur_arg, *cur_arg, *cur_arg);
        fprintf(stderr, "cur_arg = %s\n", *cur_arg);
        args.push_back(*cur_arg);
    }

    // modify current environ. And no undo later...
    char * const *env_kv;
    for(env_kv = envp; env_kv != NULL && *env_kv != NULL && **env_kv != '\0'; env_kv++ ) {
        //fprintf(stderr, "env_kv = %p  %p  %s\n", env_kv, *env_kv, *env_kv);
        fprintf(stderr, "env_kv = %s\n", *env_kv);
        // strdup required ?? putenv doesn't make a copy.
        // strdup done in osv_run_app_in_namespace
        //putenv(strdup(*env_kv));
        putenv(*env_kv);
    }

    app = osv::run(filename, args, &ret, true);
    exec_apps.push_back(app);
    fprintf(stderr, "osv_thread_run_app_in_namespace ret = %d\n", ret);
    free((void*)envp); // malloc-ed envp2 in osv_run_app_in_namespace
    fprintf(stderr, "osv_thread_run_app_in_namespace... DONE\n");
    return ret;
}

/*
 * Run filename in new thread, with its own memory (ELF namespace).
 **/
int osv_run_app_in_namespace(const char *filename,
                             char *const argv[],
                             char *const envp[])
{
    fprintf(stderr, "osv_run_app_in_namespace... \n");
    std::thread app_thread;

    int env_mod_delay;
    /*
     * delay 5,15,25 sec, so that each ompi_init has 'private' environ.
     * 5 sec, for orted.so start all worker threads.
     * 10 sec for each worker thread to run ompi_init etc.
     **/
    env_mod_delay = 5 + exec_threads.size() * 10;
    /*
     * This fun is executed in orted.so thread. The start_local loop will 
     * update values in envp etc, before new application/thread is able to use
     * them. So make a private copy. And leak some memory.
     * Ignore filename and argv.
     **/
    char ** envp2 = (char**)malloc(1100*sizeof(char*));
    char * const *env_kv;
    int ii;
    for(env_kv = envp, ii=0; env_kv != NULL && *env_kv != NULL && **env_kv != '\0'; env_kv++, ii++ ) {
        envp2[ii] = strdup(*env_kv);
        if(ii >= (1100-1)) {
            // never
            fprintf(stderr, "huge ENV... \n");
            return -1;
        }
    }
    envp2[ii] = NULL;
    
    exec_threads.push_back(std::thread(osv_thread_run_app_in_namespace, filename, argv, envp2, env_mod_delay));
    // app_thread.join(); // don't wait
    // when and how to join ? backgroud apps, and terminate libhttpserver.so ?
    fprintf(stderr, "osv_run_app_in_namespace... DONE\n");
    return 0;
}
