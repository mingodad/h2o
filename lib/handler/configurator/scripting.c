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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "h2o/scripting.h"

int h2o_scripting_configurator_t::on_config_scripting_handler(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (h2o_scripting_configurator_t *)cmd->configurator;

    /* set source */
    self->vars->source.strdup(NULL, node->data.scalar, SIZE_MAX);
    self->vars->path = node->filename;
    self->vars->lineno = (int)node->line;

    /* check if there is any error in source */
    char errbuf[1024];
    if (self->compile_test(self->vars, errbuf, sizeof(errbuf))) {
        cmd->errprintf(node, "%s compile error:%s", self->scripting_language_name, errbuf);
        if(!self->vars->debug) goto Error;
    }

    /* register */
    self->pathconf_register(ctx->pathconf, self->vars);

    return 0;

Error:
    h2o_mem_free(self->vars->source.base);
    return -1;
}

static int load_scripting_handler_file(h2o_scripting_config_vars_t *config)
{
    FILE *fp = NULL;
    h2o_iovec_t buf = {};
    int ret = -1;
    const size_t read_size = 65536;
    size_t excess;

    /* open and read file */
    if ((fp = fopen(config->path, "rt")) == NULL) {
        fprintf(stderr, "failed to open file: %s:%s", config->path, strerror(errno));
        goto Exit;
    }
    while (!feof(fp)) {
        buf.base = h2o_mem_realloc_for<char>(buf.base, buf.len + read_size);
        buf.len += fread(buf.base + buf.len, 1, read_size, fp);
        if (ferror(fp)) {
            fprintf(stderr,
                    "I/O error occurred while reading file:%s:%s",
                    config->path, strerror(errno));
            goto Exit;
        }
    }

    /*adjust the memory for small scripts there is a lot of empty space*/
    excess =  buf.len % read_size;
    if(excess > 4096)
    {
        buf.base = h2o_mem_realloc_for<char>(buf.base, buf.len+1);
    }
    /* set source */
    if(config->source.base)
    {
        h2o_mem_free(config->source.base);
    }
    config->source = buf;
    config->lineno = 0;
    buf.base = NULL;

    ret = 0;

Exit:
    if (fp != NULL)
        fclose(fp);
    if (buf.base != NULL)
        h2o_mem_free(buf.base);
    return ret;
}

int h2o_scripting_configurator_t::on_config_scripting_handler_file(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    auto self = (h2o_scripting_configurator_t *)cmd->configurator;
    int ret = -1;

    self->vars->path = node->data.scalar; /* the value is retained until the end of the configuration phase */
    self->vars->source = {};

    if(load_scripting_handler_file(self->vars))
        goto Exit;

    /* check if there is any error in source */
    char errbuf[1024];
    if (self->compile_test(self->vars, errbuf, sizeof(errbuf))) {
        cmd->errprintf(node, "failed to compile file:%s:%s",
                node->data.scalar, errbuf);
        if(!self->vars->debug) goto Exit;
    }

    /* register */
    self->pathconf_register(ctx->pathconf, self->vars);

    ret = 0;

Exit:
    return ret;
}

int h2o_scripting_configurator_t::on_config_scripting_handler_path(h2o_configurator_command_t *cmd,
        h2o_configurator_context_t *ctx, yoml_t *node)
{
    cmd->errprintf(node, "the command has been removed; see https://github.com/h2o/h2o/pull/467");
    return -1;
}

void h2o_scripting_configurator_t::on_config_scripting_debug(h2o_configurator_command_t *cmd, bool result)
{
    ((h2o_scripting_configurator_t *)cmd->configurator)->vars->debug = result;
}

int h2o_scripting_configurator_t::enter(h2o_configurator_context_t *ctx, yoml_t *node)
{
    memcpy(this->vars + 1, this->vars, sizeof(*this->vars));
    ++this->vars;
    return 0;
}

int h2o_scripting_configurator_t::exit(h2o_configurator_context_t *ctx, yoml_t *node)
{
    /* free if the to-be-exitted frame level contains a different source */
    if (this->vars[-1].source.base != this->vars[-1].source.base)
        h2o_mem_free(this->vars->source.base);

    --this->vars;
    return 0;
}


void h2o_scripting_configurator_t::register_configurator(h2o_scripting_configurator_t *c, h2o_globalconf_t *conf)
{
    char buf[256];
    c->vars = c->_vars_stack;
    c->vars->debug = 0;

    #define CMD_NAME(cn) snprintf(buf, sizeof(buf), "%s." cn, c->scripting_language_name)

    auto cf = h2o_CONFIGURATOR_FLAG(H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_DEFERRED);
    CMD_NAME("debug");
    c->define_command(buf, cf, h2o_scripting_configurator_t::on_config_scripting_debug);
    CMD_NAME("handler_path");
    c->define_command(buf, cf, h2o_scripting_configurator_t::on_config_scripting_handler_path);

    cf = h2o_CONFIGURATOR_FLAG(cf | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR);
    CMD_NAME("handler");
    c->define_command(buf, cf, h2o_scripting_configurator_t::on_config_scripting_handler);
    CMD_NAME("handler-file");
    c->define_command(buf, cf, h2o_scripting_configurator_t::on_config_scripting_handler_file);
    #undef CMD_NAME
}

int h2o_scripting_handler_t::reload_scripting_file(h2o_context_t *ctx)
{
    int ret = -1;

    if(load_scripting_handler_file(&config))
        goto Exit;

    /* check if there is any error in source */
    if (this->compile_code(ctx)) {
        if(!config.debug) goto Exit;
    }

    ret = 0;

Exit:
    return ret;
}

void h2o_scripting_handler_t::dispose(h2o_base_handler_t *_handler)
{
    auto handler = (h2o_scripting_handler_t *)_handler;

    h2o_mem_free(handler->config.source.base);
    h2o_mem_free(handler->config.path);
    h2o_mem_free(handler);
}

static void mg_strlcpy(register char *dst, register const char *src, size_t n) {
  for (; *src != '\0' && n > 1; n--) {
    *dst++ = *src++;
  }
  *dst = '\0';
}

//DAD
//static int lowercase(const char *s) {
//  return tolower(* (const unsigned char *) s);
//}
#define lowercase(s) tolower(* (const unsigned char *) s)

int mg_strncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

int mg_strcasecmp(const char *s1, const char *s2) {
  int diff;

  do {
    diff = lowercase(s1++) - lowercase(s2++);
  } while (diff == 0 && s1[-1] != '\0');

  return diff;
}

static const char *mg_strcasestr(const char *big_str, const char *small_str) {
  int i, big_len = strlen(big_str), small_len = strlen(small_str);

  for (i = 0; i <= big_len - small_len; i++) {
    if (mg_strncasecmp(big_str + i, small_str, small_len) == 0) {
      return big_str + i;
    }
  }

  return NULL;
}
/*
// Like snprintf(), but never returns negative value, or a value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
static int mg_vsnprintf(struct mg_connection *conn, char *buf, size_t buflen,
                        const char *fmt, va_list ap) {
  int n;

  if (buflen == 0)
    return 0;

  n = vsnprintf(buf, buflen, fmt, ap);

  if (n < 0) {
    cry(conn, "vsnprintf error");
    n = 0;
  } else if (n >= (int) buflen) {
    cry(conn, "truncating vsnprintf buffer: [%.*s]",
        n > 200 ? 200 : n, buf);
    n = (int) buflen - 1;
  }
  buf[n] = '\0';

  return n;
}

static int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                       PRINTF_FORMAT_STRING(const char *fmt), ...)
  PRINTF_ARGS(4, 5);

static int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                       const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vsnprintf(conn, buf, buflen, fmt, ap);
  va_end(ap);

  return n;
}
*/
// Skip the characters until one of the delimiters characters found.
// 0-terminate resulting word. Skip the delimiter and following whitespaces if any.
// Advance pointer to buffer to the next word. Return found 0-terminated word.
// Delimiters can be quoted with quotechar.
static char *skip_quoted(char **buf, const char *delimiters,
                         const char *whitespace, char quotechar) {
  char *p, *begin_word, *end_word, *end_whitespace;

  begin_word = *buf;
  end_word = begin_word + strcspn(begin_word, delimiters);

  // Check for quotechar
  if (end_word > begin_word) {
    p = end_word - 1;
    while (*p == quotechar) {
      // If there is anything beyond end_word, copy it
      if (*end_word == '\0') {
        *p = '\0';
        break;
      } else {
        size_t end_off = strcspn(end_word + 1, delimiters);
        memmove (p, end_word, end_off + 1);
        p += end_off; // p must correspond to end_word - 1
        end_word += end_off + 1;
      }
    }
    for (p++; p < end_word; p++) {
      *p = '\0';
    }
  }

  if (*end_word == '\0') {
    *buf = end_word;
  } else {
    end_whitespace = end_word + 1 + strspn(end_word + 1, whitespace);

    for (p = end_word; p < end_whitespace; p++) {
      *p = '\0';
    }

    *buf = end_whitespace;
  }

  return begin_word;
}

// Simplified version of skip_quoted without quote char
// and whitespace == delimiters
static char *skip(char **buf, const char *delimiters) {
  return skip_quoted(buf, delimiters, delimiters, 0);
}

// URL-decode input buffer into destination buffer.
// 0-terminate the destination buffer. Return the length of decoded data.
// form-url-encoded data differs from URI encoding in a way that it
// uses '+' as character for space, see RFC 1866 section 8.2.1
// http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
size_t mg_url_decode(const char *src, size_t src_len, char *dst,
                         size_t dst_len, int is_form_url_encoded) {
  size_t i, j;
  int a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%' && i < src_len - 2 &&
        isxdigit(* (const unsigned char *) (src + i + 1)) &&
        isxdigit(* (const unsigned char *) (src + i + 2))) {
      a = tolower(* (const unsigned char *) (src + i + 1));
      b = tolower(* (const unsigned char *) (src + i + 2));
      dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
      i += 2;
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

  dst[j] = '\0'; // Null-terminate the destination

  return j;
}

// Scan given buffer and fetch the value of the given variable.
// It can be specified in query string, or in the POST data.
// Return NULL if the variable not found, or allocated 0-terminated value.
// It is caller's responsibility to free the returned value.
int mg_find_var(const char *buf, size_t buf_len, const char *name,
                const char **start) {
  const char *p, *e, *s;
  size_t name_len, len;

  name_len = strlen(name);
  e = buf + buf_len;
  len = -1;

  // buf is "var1=val1&var2=val2...". Find variable first
  for (p = buf; p != NULL && p + name_len < e; p++) {
    if ((p == buf || p[-1] == '&') && p[name_len] == '=' &&
        !mg_strncasecmp(name, p, name_len)) {

      // Point p to variable value
      p += name_len + 1;

      // Point s to the end of the value
      s = (const char *) memchr(p, '&', (size_t)(e - p));
      if (s == NULL) {
        s = e;
      }
      assert(s >= p);
      *start = p;
      len = (s - p);
      break;
    }
  }

  return len;
}

int mg_get_var(const char *buf, size_t buf_len, const char *name,
               char *dst, size_t dst_len) {
  const char *start;
  int len;

  len = mg_find_var(buf, buf_len, name, &start);

  if( (len > 0) && (size_t(len) < dst_len) ) {
    len = mg_url_decode(start, len, dst, dst_len, 1);
  } else dst[0] = '\0';

  return len;
}

int mg_find_cookie(h2o_req_t *req, const char *cookie_name,
                  const char **start) {
  const char *s, *p, *end;
  int name_len, len = -1;
  ssize_t idx = req->headers.find(H2O_TOKEN_COOKIE, SIZE_MAX);

  if (idx <= 0) {
    return -1;
  }
  s = req->headers[idx].value.base;

  name_len = (int) strlen(cookie_name);
  end = s + strlen(s);

  for (; (s = strstr(s, cookie_name)) != NULL; s += name_len)
    if (s[name_len] == '=') {
      s += name_len + 1;
      if ((p = strchr(s, ' ')) == NULL)
        p = end;
      if (p[-1] == ';')
        p--;
      if (*s == '"' && p[-1] == '"' && p > s + 1) {
        s++;
        p--;
      }
      len = (p - s) + 1;
      *start = s;
      break;
    }

  return len;
}

int mg_get_cookie(h2o_req_t *req, const char *cookie_name,
                  char *dst, size_t dst_size) {
  const char *start;
  int len;

  len = mg_find_cookie(req, cookie_name, &start);

  if( (len > 0) && (size_t(len) < dst_size) ) {
      mg_strlcpy(dst, start, (size_t)len);
      dst[len] = '\0';
  } else dst[0] = '\0';

  return len;
}

const char *mg_url_encode_to(const char *src, char *dst, size_t dst_len) {
  static const char *dont_escape = "._-$,;~()";
  static const char *hex = "0123456789abcdef";
  const char *end = dst + dst_len - 1;

  for (; *src != '\0' && dst < end; src++, dst++) {
    if (isalnum(*(const unsigned char *) src) ||
        strchr(dont_escape, * (const unsigned char *) src) != NULL) {
      *dst = *src;
    } else if (dst + 2 < end) {
      dst[0] = '%';
      dst[1] = hex[(* (const unsigned char *) src) >> 4];
      dst[2] = hex[(* (const unsigned char *) src) & 0xf];
      dst += 2;
    } else break;
  }

  *dst = '\0';
  return src;
}

char *mg_url_encode(const char *src) {
    size_t dst_len = (strlen(src)*2)+1;
    char *dst = h2o_mem_alloc_for<char>(dst_len);
    if(dst){
        const char *done = mg_url_encode_to(src, dst, dst_len);
        while(*done){
            int old_dst_len = dst_len;
            dst_len = dst_len + (dst_len / 2);
            dst = (char*)h2o_mem_realloc(dst, dst_len);
            if(!dst) break;
            done = mg_url_encode_to(done, dst+strlen(dst), dst_len-old_dst_len);
        }
    }
    return dst;
}
