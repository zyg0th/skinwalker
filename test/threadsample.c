// threadsample - test target for skinwalker: exercises pthread_create
// and fork() so we can check TLS/auxv setup survives the userland load.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#define NTHREADS 4

static void *worker(void *arg)
{
    long id = (long)arg;
    for (int i = 0; i < 3; i++)
    {
        printf("[thread %ld] tid=%ld iter=%d pid=%d\n",
               id, (long)pthread_self(), i, getpid());
        fflush(stdout);
        usleep(300 * 1000);
    }
    return NULL;
}

int main(void)
{
    printf("main pid=%d, spawning %d threads\n", getpid(), NTHREADS);
    fflush(stdout);

    pthread_t th[NTHREADS];
    for (long i = 0; i < NTHREADS; i++)
        pthread_create(&th[i], NULL, worker, (void *)i);

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(th[i], NULL);

    printf("threads done, forking\n");
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0)
    {
        printf("[child] pid=%d ppid=%d\n", getpid(), getppid());
        fflush(stdout);
        _exit(0);
    }
    else if (pid > 0)
    {
        waitpid(pid, NULL, 0);
        printf("[parent] pid=%d, child reaped\n", getpid());
    }
    else
    {
        perror("fork");
        return 1;
    }

    printf("done\n");
    return 0;
}
