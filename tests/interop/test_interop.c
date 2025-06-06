#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int start_process(const char *exe, char *const envp[])
{
    pid_t pid = fork();
    if (pid == 0)
    {
        execle(exe, exe, NULL, envp);
        perror("execle");
        _exit(1);
    }
    return pid;
}

static int test_muxer(const char *muxer_name)
{
    printf("Testing muxer: %s\n", muxer_name);

    // start redis-server
    pid_t redis = fork();
    if (redis == 0)
    {
        execlp("redis-server", "redis-server", "--save", "", "--appendonly", "no", "--port", "6379", NULL);
        perror("redis-server");
        _exit(1);
    }
    sleep(1);

    // prepare environment
    char muxer_env[64];
    snprintf(muxer_env, sizeof(muxer_env), "muxer=%s", muxer_name);
    char *env_base[] = {"transport=tcp", muxer_env, "security=noise", "test_timeout_seconds=5", NULL};

    // listener
    char *env_listener[] = {"is_dialer=false", "redis_addr=127.0.0.1:6379", "ip=0.0.0.0", env_base[0], env_base[1], env_base[2], env_base[3], NULL};
    pid_t listener = start_process("./interop-c", env_listener);
    sleep(1);

    // dialer
    char *env_dialer[] = {"is_dialer=true", "redis_addr=127.0.0.1:6379", env_base[0], env_base[1], env_base[2], env_base[3], NULL};
    int pipefd[2];
    pipe(pipefd);
    pid_t dialer = fork();

    if (dialer == 0)
    {
        dup2(pipefd[1], 1);
        close(pipefd[0]);
        execle("./interop-c", "./interop-c", NULL, env_dialer);
        perror("execle");
        _exit(1);
    }

    close(pipefd[1]);
    char buf[256];
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    if (n > 0)
        buf[n] = 0;
    else
        buf[0] = 0;
    close(pipefd[0]);

    int status;
    waitpid(dialer, &status, 0);
    kill(listener, SIGTERM);
    waitpid(listener, NULL, 0);
    kill(redis, SIGTERM);
    waitpid(redis, NULL, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && strstr(buf, "handshakePlusOneRTTMillis"))
    {
        printf("TEST: interop ping (%s) | PASS\n", muxer_name);
        return 0;
    }
    printf("TEST: interop ping (%s) | FAIL\nOutput: %s\n", muxer_name, buf);
    return 1;
}

int main(void)
{
    int yamux_result = test_muxer("yamux");
    sleep(2); // Give some time between tests
    int mplex_result = test_muxer("mplex");

    if (yamux_result == 0 && mplex_result == 0)
    {
        printf("All interop tests passed!\n");
        return 0;
    }
    else
    {
        printf("Some interop tests failed!\n");
        return 1;
    }
}