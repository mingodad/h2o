/*
 * Copyright (c) 2015 DeNA Co., Ltd. Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/un.h>
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/serverutil.h"

struct fastcgi_configurator_t : h2o_configurator_t {
    h2o_fastcgi_config_vars_t *vars;
    h2o_fastcgi_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;
};

static int on_config_timeout_io(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (fastcgi_configurator_t *)cmd->configurator;
    return cmd->scanf(node, "%" PRIu64, &self->vars->io_timeout);
}

static int on_config_timeout_keepalive(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (fastcgi_configurator_t *)cmd->configurator;
    return cmd->scanf(node, "%" PRIu64, &self->vars->keepalive_timeout);
}

static int on_config_document_root(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (fastcgi_configurator_t *)cmd->configurator;

    if (node->data.scalar[0] == '\0') {
        /* unset */
        self->vars->document_root.init(NULL, 0);
    } else if (node->data.scalar[0] == '/') {
        /* set */
        self->vars->document_root.init(node->data.scalar, strlen(node->data.scalar));
    } else {
        cmd->errprintf(node, "value does not start from `/`");
        return -1;
    }
    return 0;
}

static int on_config_send_delegated_uri(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t v = cmd->get_one_of(node, "OFF,ON");
    if (v == -1)
        return -1;
    ((fastcgi_configurator_t *)cmd->configurator)->vars->send_delegated_uri = (int)v;
    return 0;
}

static int on_config_connect(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (fastcgi_configurator_t *)cmd->configurator;
    const char *hostname = "127.0.0.1", *servname = NULL, *type = "tcp";

    /* fetch servname (and hostname) */
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        servname = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t *t;
        if ((t = yoml_get(node, "host")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                cmd->errprintf(t, "`host` is not a string");
                return -1;
            }
            hostname = t->data.scalar;
        }
        if ((t = yoml_get(node, "port")) == NULL) {
            cmd->errprintf(node, "cannot find mandatory property `port`");
            return -1;
        }
        if (t->type != YOML_TYPE_SCALAR) {
            cmd->errprintf(node, "`port` is not a string");
            return -1;
        }
        servname = t->data.scalar;
        if ((t = yoml_get(node, "type")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                cmd->errprintf(t, "`type` is not a string");
                return -1;
            }
            type = t->data.scalar;
        }
    } break;
    default:
        cmd->errprintf(node,
                                   "value must be a string or a mapping (with keys: `port` and optionally `host` and `type`)");
        return -1;
    }

    if (strcmp(type, "unix") == 0) {
        /* unix socket */
        struct sockaddr_un sa = {};
        if (strlen(servname) >= sizeof(sa.sun_path)) {
            cmd->errprintf(node, "path:%s is too long as a unix socket name", servname);
            return -1;
        }
        sa.sun_family = AF_UNIX;
        strcpy(sa.sun_path, servname);
        h2o_fastcgi_register_by_address(ctx->pathconf, (sockaddr *)&sa, sizeof(sa), self->vars);
    } else if (strcmp(type, "tcp") == 0) {
        /* tcp socket */
        uint16_t port;
        if (sscanf(servname, "%" SCNu16, &port) != 1) {
            cmd->errprintf(node, "invalid port number:%s", servname);
            return -1;
        }
        h2o_fastcgi_register_by_hostport(ctx->pathconf, hostname, port, self->vars);
    } else {
        cmd->errprintf(node, "unknown listen type: %s", type);
        return -1;
    }

    return 0;
}

static int create_spawnproc(h2o_configurator_command_t *cmd, yoml_t *node, const char *dirname, char *const *argv,
                            struct sockaddr_un *sa, struct passwd *pw)
{
    int listen_fd, pipe_fds[2] = {-1, -1};

    /* build socket path */
    sa->sun_family = AF_UNIX;
    strcpy(sa->sun_path, dirname);
    strcat(sa->sun_path, "/_");

    /* create socket */
    if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        cmd->errprintf(node, "socket(2) failed: %s", strerror(errno));
        goto Error;
    }
    if (bind(listen_fd, (sockaddr *)sa, sizeof(*sa)) != 0) {
        cmd->errprintf(node, "bind(2) failed: %s", strerror(errno));
        goto Error;
    }
    if (listen(listen_fd, H2O_SOMAXCONN) != 0) {
        cmd->errprintf(node, "listen(2) failed: %s", strerror(errno));
        goto Error;
    }
    /* change ownership of socket */
    if (pw != NULL && chown(sa->sun_path, pw->pw_uid, pw->pw_gid) != 0) {
        cmd->errprintf(node, "chown(2) failed to change ownership of socket:%s:%s", sa->sun_path, strerror(errno));
        goto Error;
    }

    /* create pipe which is used to notify the termination of the server */
    if (pipe(pipe_fds) != 0) {
        cmd->errprintf(node, "pipe(2) failed: %s", strerror(errno));
        pipe_fds[0] = -1;
        pipe_fds[1] = -1;
        goto Error;
    }
    fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

    /* spawn */
    {
        int mapped_fds[] = {listen_fd, 0,   /* listen_fd to 0 */
                            pipe_fds[0], 5, /* pipe_fds[0] to 5 */
                            -1};
        pid_t pid = h2o_spawnp(argv[0], argv, mapped_fds, 0);
        if (pid == -1) {
            fprintf(stderr, "[lib/handler/fastcgi.c] failed to launch helper program %s:%s\n", argv[0], strerror(errno));
            goto Error;
        }
    }

    close(listen_fd);
    listen_fd = -1;
    close(pipe_fds[0]);
    pipe_fds[0] = -1;

    return pipe_fds[1];

Error:
    if (pipe_fds[0] != -1)
        close(pipe_fds[0]);
    if (pipe_fds[1])
        close(pipe_fds[1]);
    if (listen_fd != -1)
        close(listen_fd);
    unlink(sa->sun_path);
    return -1;
}

void spawnproc_on_dispose(h2o_fastcgi_handler_t *handler, void *data)
{
    int pipe_fd = (int)((char *)data - (char *)NULL);
    close(pipe_fd);
}

static int on_config_spawn(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (fastcgi_configurator_t *)cmd->configurator;
    const char *spawn_user = NULL, *spawn_cmd;
    char *kill_on_close_cmd_path = NULL, *setuidgid_cmd_path = NULL;
    char dirname[] = "/tmp/h2o.fcgisock.XXXXXX";
    const char *argv[10];
    int spawner_fd;
    struct sockaddr_un sa = {};
    h2o_fastcgi_config_vars_t config_vars;
    int ret = -1;
    struct passwd spawn_pwbuf, *spawn_pw;
    char spawn_buf[1024*4];

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        spawn_user = ctx->globalconf->user;
        spawn_cmd = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t *t;
        if ((t = yoml_get(node, "command")) == NULL) {
            cmd->errprintf(node, "mandatory attribute `command` does not exist");
            return -1;
        }
        if (t->type != YOML_TYPE_SCALAR) {
            cmd->errprintf(node, "attribute `command` must be scalar");
            return -1;
        }
        spawn_cmd = t->data.scalar;
        spawn_user = ctx->globalconf->user;
        if ((t = yoml_get(node, "user")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                cmd->errprintf(node, "attribute `user` must be scalar");
                return -1;
            }
            spawn_user = t->data.scalar;
        }
    } break;
    default:
        cmd->errprintf(node, "argument must be scalar or mapping");
        return -1;
    }

    /* obtain uid & gid of spawn_user */
    if (spawn_user != NULL) {
        /* change ownership of temporary directory */
        if (getpwnam_r(spawn_user, &spawn_pwbuf, spawn_buf, sizeof(spawn_buf), &spawn_pw) != 0) {
            cmd->errprintf(node, "getpwnam_r(3) failed to get password file entry");
            goto Exit;
        }
        if (spawn_pw == NULL) {
            cmd->errprintf(node, "unknown user:%s", spawn_user);
            goto Exit;
        }
    } else {
        spawn_pw = NULL;
    }

    { /* build args */
        size_t i = 0;
        argv[i++] = kill_on_close_cmd_path = h2o_configurator_get_cmd_path("share/h2o/kill-on-close");
        argv[i++] = "--rm";
        argv[i++] = dirname;
        argv[i++] = "--";
        if (spawn_pw != NULL) {
            argv[i++] = setuidgid_cmd_path = h2o_configurator_get_cmd_path("share/h2o/setuidgid");
            argv[i++] = spawn_pw->pw_name;
        }
        argv[i++] = "/bin/sh";
        argv[i++] = "-c";
        argv[i++] = spawn_cmd;
        argv[i++] = NULL;
        assert(i <= sizeof(argv) / sizeof(argv[0]));
    }

    if (ctx->dry_run) {
        dirname[0] = '\0';
        spawner_fd = -1;
        sa.sun_family = AF_UNIX;
        strcpy(sa.sun_path, "/dry-run.nonexistent");
    } else {
        /* create temporary directory */
        if (mkdtemp(dirname) == NULL) {
            cmd->errprintf(node, "mkdtemp(3) failed to create temporary directory:%s:%s", dirname,
                                       strerror(errno));
            dirname[0] = '\0';
            goto Exit;
        }
        /* change ownership of temporary directory */
        if (spawn_pw != NULL && chown(dirname, spawn_pw->pw_uid, spawn_pw->pw_gid) != 0) {
            cmd->errprintf(node, "chown(2) failed to change ownership of temporary directory:%s:%s", dirname,
                                       strerror(errno));
            goto Exit;
        }
        /* launch spawnfcgi command */
        if ((spawner_fd = create_spawnproc(cmd, node, dirname, (char*const*)argv, &sa, spawn_pw)) == -1) {
            goto Exit;
        }
    }

    config_vars = *self->vars;
    config_vars.callbacks.dispose = spawnproc_on_dispose;
    config_vars.callbacks.data = (char *)NULL + spawner_fd;
    h2o_fastcgi_register_by_address(ctx->pathconf, (sockaddr *)&sa, sizeof(sa), &config_vars);

    ret = 0;
Exit:
    if (dirname[0] != '\0')
        unlink(dirname);
    h2o_mem_free(kill_on_close_cmd_path);
    h2o_mem_free(setuidgid_cmd_path);
    return ret;
}

int fastcgi_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    memcpy(this->vars + 1, this->vars, sizeof(*this->vars));
    ++this->vars;
    return 0;
}

int fastcgi_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    --this->vars;
    return 0;
}

void h2o_fastcgi_register_configurator(h2o_globalconf_t *conf)
{
    auto c = conf->configurator_create<fastcgi_configurator_t>();

    /* set default vars */
    c->vars = c->_vars_stack;
    c->vars->io_timeout = H2O_DEFAULT_FASTCGI_IO_TIMEOUT;
    c->vars->keepalive_timeout = 0;

    /* setup handlers */

    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXTENSION
                                    | H2O_CONFIGURATOR_FLAG_DEFERRED);
    c->define_command("fastcgi.connect", cf, on_config_connect);
    c->define_command("fastcgi.spawn", cf, on_config_spawn);

    cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_ALL_LEVELS | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    c->define_command("fastcgi.timeout.io", cf, on_config_timeout_io);
    c->define_command("fastcgi.timeout.keepalive", cf, on_config_timeout_keepalive);
    c->define_command("fastcgi.document_root", cf, on_config_document_root);
    c->define_command("fastcgi.send-delegated-uri", cf, on_config_send_delegated_uri);
}
