/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#ifndef h2o__configurator_h
#define h2o__configurator_h

#include "yoml.h"

enum h2o_CONFIGURATOR_FLAG {
    H2O_CONFIGURATOR_FLAG_GLOBAL = 0x1,
    H2O_CONFIGURATOR_FLAG_HOST = 0x2,
    H2O_CONFIGURATOR_FLAG_PATH = 0x4,
    H2O_CONFIGURATOR_FLAG_EXTENSION = 0x8,
    H2O_CONFIGURATOR_FLAG_ALL_LEVELS =
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXTENSION,
    H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR = 0x100,
    H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE = 0x200,
    H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING = 0x400,
    H2O_CONFIGURATOR_FLAG_DEFERRED = 0x1000,
    H2O_CONFIGURATOR_FLAG_SEMI_DEFERRED = 0x2000 /* used by file.custom-handler (invoked before hosts,paths,file-dir, etc.) */
};

#define H2O_CONFIGURATOR_NUM_LEVELS 4

struct h2o_configurator_context_t {
    h2o_globalconf_t *globalconf;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;
    h2o_mimemap_t **mimemap;
    int dry_run;
    h2o_configurator_context_t *parent;
    /**
     *
     */
    int apply_commands(yoml_t *node, int flags_mask, const char **ignore_commands);
};

typedef int (*h2o_configurator_dispose_cb)(h2o_configurator_t *configurator);
typedef int (*h2o_configurator_enter_cb)(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node);
typedef int (*h2o_configurator_exit_cb)(h2o_configurator_t *configurator, h2o_configurator_context_t *ctx, yoml_t *node);
typedef int (*h2o_configurator_command_cb)(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);

struct h2o_configurator_command_t {
    /**
     * configurator to which the command belongs
     */
    h2o_configurator_t *configurator;
    /**
     * name of the command handled by the configurator
     */
    const char *name;
    /**
     * flags
     */
    int flags;
    /**
     * mandatory callback called to handle the command
     */
    h2o_configurator_command_cb cb;

    /**
     * interprets the configuration value and returns the index of the matched string within the candidate strings, or prints an error
     * upon failure
     * @param configurator configurator
     * @param node configuration value
     * @param candidates a comma-separated list of strings (should not contain whitespaces)
     * @return index of the matched string within the given list, or -1 if none of them matched
     */
    ssize_t get_one_of(yoml_t *node, const char *candidates);
    /**
     * emits configuration error
     */
    void errprintf(yoml_t *node, const char *reason, ...) __attribute__((format(printf, 3, 4)));
    /**
     * interprets the configuration value using sscanf, or prints an error upon failure
     * @param configurator configurator
     * @param node configuration value
     * @param fmt scanf-style format string
     * @return 0 if successful, -1 if not
     */
    int scanf(yoml_t *node, const char *fmt, ...) __attribute__((format(scanf, 3, 4)));
};

/**
 * basic structure of a configurator (handles a configuration command)
 */
struct h2o_configurator_t {
    h2o_linklist_t _link;
    /**
     * optional callback called when the global config is being disposed
     */
    h2o_configurator_dispose_cb dispose;
    /**
     * optional callback called before the configuration commands are handled
     */
    h2o_configurator_enter_cb enter;
    /**
     * optional callback called after all the configuration commands are handled
     */
    h2o_configurator_exit_cb exit;
    /**
     * list of commands
     */
    H2O_VECTOR<h2o_configurator_command_t> commands;
    /**
     *
     */
    void define_command(const char *name, int flags, h2o_configurator_command_cb cb);
};

inline bool isScalar(yoml_t *node, const char *value)
{
    return node->type == YOML_TYPE_SCALAR && strcasecmp(node->data.scalar, value) == 0;
}

/**
 * emits configuration error
 */
void h2o_configurator_errprintf(yoml_t *node, const char *reason, ...)
    __attribute__((format(printf, 2, 3)));
/**
 * returns the absolute paths of supplementary commands
 */
char *h2o_configurator_get_cmd_path(const char *cmd);

#endif
