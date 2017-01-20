#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>

#include "sysrepo.h"

int rpc_start(const char *xpath, const sr_val_t *input, const size_t input_cnt,
              sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl("/etc/init.d/asterisk", "asterisk", "start", (char *) NULL);
        return SR_ERR_OPERATION_FAILED;
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

int rpc_stop(const char *xpath, const sr_val_t *input, const size_t input_cnt,
             sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl("/etc/init.d/asterisk", "asterisk", "stop", (char *) NULL);
        return SR_ERR_OPERATION_FAILED;
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

int rpc_restart(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl("/etc/init.d/asterisk", "asterisk", "restart", (char *) NULL);
        return SR_ERR_OPERATION_FAILED;
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

int rpc_reload(const char *xpath, const sr_val_t *input, const size_t input_cnt,
               sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl("/etc/init.d/asterisk", "asterisk", "reload", (char *) NULL);
        return SR_ERR_OPERATION_FAILED;
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

int rpc_disable(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl("/etc/init.d/asterisk", "asterisk", "disable", (char *) NULL);
        return SR_ERR_OPERATION_FAILED;
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

int rpc_enable(const char *xpath, const sr_val_t *input, const size_t input_cnt,
               sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    pid_t pid = fork();
    if (pid == 0) {
        execl("/etc/init.d/asterisk", "asterisk", "enable", (char *) NULL);
        return SR_ERR_OPERATION_FAILED;
    } else {
        waitpid(pid, 0, 0);
    }

    return SR_ERR_OK;
}

/**
 * @brief RPC method consists of method identifier and signature.
 *
 * Method is meant to be used as a Sysrepo RPC callback. 
 */
struct rpc_method {
    char *name;
    int (*method)(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                  sr_val_t **output, size_t *output_cnt, void *private_ctx);
};
