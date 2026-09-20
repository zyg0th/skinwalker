// forksample - test target for skinwalker: plain fork(), no threads.
// parent spawns N children, each prints then exits; parent reaps all.
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#define NCHILDREN 3

int main(void)
{
    printf("main pid=%d, forking %d children\n", getpid(), NCHILDREN);
    fflush(stdout);

    for (int i = 0; i < NCHILDREN; i++)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            return 1;
        }
        if (pid == 0)
        {
            printf("[child %d] pid=%d ppid=%d\n", i, getpid(), getppid());
            fflush(stdout);
            _exit(0);
        }
    }

    int status;
    pid_t w;
    while ((w = wait(&status)) > 0)
        printf("[parent] reaped pid=%d status=%d\n", w, status);
    fflush(stdout);

    printf("done\n");
    return 0;
}
