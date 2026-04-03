#include <gtest/gtest.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "sandbox/seccomp_filter.hpp"

TEST(SeccompFilterTest, DefaultProfileConfig) {
    SeccompConfig config = SeccompFilter::defaultSandboxProfile();

    EXPECT_TRUE(config.allow_read);
    EXPECT_TRUE(config.allow_write);
    EXPECT_FALSE(config.allow_socket);
    EXPECT_FALSE(config.allow_connect);
    EXPECT_FALSE(config.allow_execve);
    EXPECT_FALSE(config.allow_fork);
}

TEST(SeccompFilterTest, StrictProfileConfig) {
    SeccompConfig config = SeccompFilter::strictProfile();

    EXPECT_TRUE(config.allow_read);
    EXPECT_TRUE(config.allow_write);
    EXPECT_FALSE(config.allow_open);
    EXPECT_FALSE(config.allow_socket);
    EXPECT_FALSE(config.allow_execve);
}

TEST(SeccompFilterTest, ApplyInChildProcess) {
    pid_t pid = fork();

    if (pid == 0) {
        SeccompConfig config = SeccompFilter::defaultSandboxProfile();
        bool result = SeccompFilter::apply(config);
        if (!result) _exit(1);
        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}

TEST(SeccompFilterTest, BlockedSyscallKillsProcess) {
    pid_t pid = fork();

    if (pid == 0) {
        SeccompConfig config = SeccompFilter::defaultSandboxProfile();
        SeccompFilter::apply(config);

        // socket 생성 시도 → 차단되어 SIGKILL
        socket(AF_INET, SOCK_STREAM, 0);

        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);

        // 시그널로 종료됐으면 성공
        EXPECT_TRUE(WIFSIGNALED(status));
    }
}
