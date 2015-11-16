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

std::vector<std::shared_ptr<osv::application>> exec_apps;
std::vector<std::thread> exec_threads;

int osv_thread_run_app_in_namespace(const char *filename,
                                    const std::vector<std::string> *args,
                                    std::unordered_map<std::string, std::string> *envp)
{
    std::shared_ptr<osv::application> app;
    int ret;

    fprintf(stderr, "osv_thread_run_app_in_namespace... \n");
    app = osv::run(filename, *args, &ret, true, envp);
    exec_apps.push_back(app);
    fprintf(stderr, "osv_thread_run_app_in_namespace ret = %d\n", ret);
    // free data allocated in osv_run_app_in_namespace
    delete args;
    delete envp;
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

    /*
     * We ahve to start new program in new thread, otherwise current thread 
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
    
    exec_threads.push_back(std::thread(osv_thread_run_app_in_namespace, filename, args, envp_map));
    
    // when and how to join ? backgroud apps, and terminate libhttpserver.so ?
    fprintf(stderr, "osv_run_app_in_namespace... DONE\n");
    return 0;
}
