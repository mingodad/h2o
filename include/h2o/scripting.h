/*
 * Copyright (c) 2016 Domingo Alvarez Duarte based on
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#ifndef H20_SCRIPTING_H
#define H20_SCRIPTING_H

#include "h2o.h"
#include "h2o/configurator.h"

#define H2O_SCRIPTING_ENTRY_POINT "h2oHandleRequest"

struct h2o_scripting_config_vars_t {
    h2o_iovec_t source;
    char *path;
    int lineno;
    int debug;
};

struct h2o_scripting_handler_t : h2o_handler_t {
    h2o_scripting_config_vars_t config;

    h2o_scripting_handler_t(): config({}) {}

    void dispose(h2o_base_handler_t *self) override;
    virtual int compile_code(h2o_context_t *ctx) = 0;
    virtual int reload_scripting_file(h2o_context_t *ctx);
};

struct h2o_scripting_configurator_t : h2o_configurator_t {
    h2o_scripting_config_vars_t *vars;
    h2o_scripting_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
    const char *scripting_language_name;

    h2o_scripting_configurator_t(const char *language_name):
        h2o_configurator_t(),scripting_language_name(language_name){}

    int enter(h2o_configurator_context_t *ctx, yoml_t *node) override;
    int exit(h2o_configurator_context_t *ctx, yoml_t *node) override;

    virtual int compile_test(h2o_scripting_config_vars_t *config, char *errbuf, size_t errbuf_size) = 0;
    virtual h2o_scripting_handler_t *pathconf_register(h2o_pathconf_t *pathconf, h2o_scripting_config_vars_t *vars) = 0;

    static int on_config_scripting_handler(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);
    static int on_config_scripting_handler_file(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);
    static int on_config_scripting_handler_path(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);
    static void on_config_scripting_debug(h2o_configurator_command_t *cmd, bool result);

    static void register_configurator(h2o_scripting_configurator_t *c, h2o_globalconf_t *conf);
};

int mg_strncasecmp(const char *s1, const char *s2, size_t len);
int mg_strcasecmp(const char *s1, const char *s2);
// Send a 401 Unauthorized response to the browser.
//
// This triggers a username/password entry in the browser.  The realm
// in the request is set to the AUTHENTICATION_DOMAIN option.
// If nonce is non-NULL, it is sent as the nonce of the authentication
// request, else a nonce is generated.
//void mg_send_authorization_request(struct mg_connection *conn, const char *nonce);
// Get a value of particular form variable.
//
// Parameters:
//   data: pointer to form-uri-encoded buffer. This could be either POST data,
//         or request_info.query_string.
//   data_len: length of the encoded data.
//   var_name: variable name to decode from the buffer
//   buf: destination buffer for the decoded variable
//   buf_len: length of the destination buffer
//
// Return:
//   On success, length of the decoded variable.
//   On error:
//      -1 (variable not found, or destination buffer is too small).
//      -2 (destination buffer is NULL or zero length).
//
// Destination buffer is guaranteed to be '\0' - terminated. In case of
// failure, dst[0] == '\0'.
int mg_find_var(const char *buf, size_t buf_len, const char *name,
                const char **start);
int mg_get_var(const char *data, size_t data_len,
    const char *var_name, char *buf, size_t buf_len);

// Fetch value of certain cookie variable into the destination buffer.
//
// Destination buffer is guaranteed to be '\0' - terminated. In case of
// failure, dst[0] == '\0'. Note that RFC allows many occurrences of the same
// parameter. This function returns only first occurrence.
//
// Return:
//   On success, value length.
//   On error, -1 (either "Cookie:" header is not present at all, or the
//   requested parameter is not found, or destination buffer is too small
//   to hold the value).
int mg_get_cookie(const struct mg_connection *,
    const char *cookie_name, char *buf, size_t buf_len);
int mg_find_cookie(const struct mg_connection *,
    const char *cookie_name, const char **start);
// URL-decode input buffer into destination buffer.
// 0-terminate the destination buffer. Return the length of decoded data.
// form-url-encoded data differs from URI encoding in a way that it
// uses '+' as character for space, see RFC 1866 section 8.2.1
// http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
size_t mg_url_decode(const char *src, size_t src_len, char *dst,
                         size_t dst_len, int is_form_url_encoded);

const char * mg_url_encode_to(const char *src, char *dst, size_t dst_len);
char * mg_url_encode(const char *src);

#endif // H20_SCRIPTING_H
