/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the &quot;Software&quot;), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED &quot;AS IS&quot;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* DO NOT EDIT! generated by tokens.pl */

#define TOK(http2_static_table_name_index, proxy_should_drop, is_init_header_special, http2_should_reject, copy_for_push_request, str_id) \
    {{H2O_STRLIT(str_id)}, http2_static_table_name_index, proxy_should_drop, is_init_header_special, http2_should_reject, copy_for_push_request}

h2o_token_t h2o__tokens[] = {
    TOK( 1,  0,  0,  0,  0,  ":authority" ),
    TOK( 2,  0,  0,  0,  0,  ":method" ),
    TOK( 4,  0,  0,  0,  0,  ":path" ),
    TOK( 6,  0,  0,  0,  0,  ":scheme" ),
    TOK( 8,  0,  0,  0,  0,  ":status" ),
    TOK( 19,  0,  0,  0,  1,  "accept" ),
    TOK( 15,  0,  0,  0,  1,  "accept-charset" ),
    TOK( 16,  0,  0,  0,  1,  "accept-encoding" ),
    TOK( 17,  0,  0,  0,  1,  "accept-language" ),
    TOK( 18,  0,  0,  0,  0,  "accept-ranges" ),
    TOK( 20,  0,  0,  0,  0,  "access-control-allow-origin" ),
    TOK( 21,  0,  0,  0,  0,  "age" ),
    TOK( 22,  0,  0,  0,  0,  "allow" ),
    TOK( 23,  0,  0,  0,  0,  "authorization" ),
    TOK( 24,  0,  0,  0,  0,  "cache-control" ),
    TOK( 0,  1,  0,  1,  0,  "connection" ),
    TOK( 25,  0,  0,  0,  0,  "content-disposition" ),
    TOK( 26,  0,  0,  0,  0,  "content-encoding" ),
    TOK( 27,  0,  0,  0,  0,  "content-language" ),
    TOK( 28,  0,  1,  0,  0,  "content-length" ),
    TOK( 29,  0,  0,  0,  0,  "content-location" ),
    TOK( 30,  0,  0,  0,  0,  "content-range" ),
    TOK( 31,  0,  0,  0,  0,  "content-type" ),
    TOK( 32,  0,  0,  0,  0,  "cookie" ),
    TOK( 33,  1,  0,  0,  0,  "date" ),
    TOK( 34,  0,  0,  0,  0,  "etag" ),
    TOK( 35,  0,  1,  0,  0,  "expect" ),
    TOK( 36,  0,  0,  0,  0,  "expires" ),
    TOK( 37,  0,  0,  0,  0,  "from" ),
    TOK( 38,  0,  1,  0,  0,  "host" ),
    TOK( 0,  1,  0,  1,  0,  "http2-settings" ),
    TOK( 39,  0,  0,  0,  0,  "if-match" ),
    TOK( 40,  0,  0,  0,  0,  "if-modified-since" ),
    TOK( 41,  0,  0,  0,  0,  "if-none-match" ),
    TOK( 42,  0,  0,  0,  0,  "if-range" ),
    TOK( 43,  0,  0,  0,  0,  "if-unmodified-since" ),
    TOK( 0,  1,  0,  0,  0,  "keep-alive" ),
    TOK( 44,  0,  0,  0,  0,  "last-modified" ),
    TOK( 45,  0,  0,  0,  0,  "link" ),
    TOK( 46,  0,  0,  0,  0,  "location" ),
    TOK( 47,  0,  0,  0,  0,  "max-forwards" ),
    TOK( 48,  1,  0,  0,  0,  "proxy-authenticate" ),
    TOK( 49,  1,  0,  0,  0,  "proxy-authorization" ),
    TOK( 50,  0,  0,  0,  0,  "range" ),
    TOK( 51,  0,  0,  0,  0,  "referer" ),
    TOK( 52,  0,  0,  0,  0,  "refresh" ),
    TOK( 53,  0,  0,  0,  0,  "retry-after" ),
    TOK( 54,  1,  0,  0,  0,  "server" ),
    TOK( 55,  0,  0,  0,  0,  "set-cookie" ),
    TOK( 56,  0,  0,  0,  0,  "strict-transport-security" ),
    TOK( 0,  1,  0,  1,  0,  "te" ),
    TOK( 57,  1,  1,  1,  0,  "transfer-encoding" ),
    TOK( 0,  1,  1,  1,  0,  "upgrade" ),
    TOK( 58,  0,  0,  0,  1,  "user-agent" ),
    TOK( 59,  0,  0,  0,  0,  "vary" ),
    TOK( 60,  0,  0,  0,  0,  "via" ),
    TOK( 61,  0,  0,  0,  0,  "www-authenticate" ),
    TOK( 0,  0,  0,  0,  0,  "x-forwarded-for" ),
    TOK( 0,  0,  0,  0,  0,  "x-reproxy-url" )
};
#undef TOK
size_t h2o__num_tokens = 59;

const h2o_token_t *h2o_lookup_token(const char *name, size_t len)
{
    switch (len) {
    case 2:
        switch (h2o_tolower(name[1])) {
        case 'e':
            if (h2o__lcstris_core(name, "t", 1) )
                return H2O_TOKEN_TE;
            break;
        }
        break;
    case 3:
        switch (h2o_tolower(name[2])) {
        case 'a':
            if (h2o__lcstris_core(name, "vi", 2) )
                return H2O_TOKEN_VIA;
            break;
        case 'e':
            if (h2o__lcstris_core(name, "ag", 2) )
                return H2O_TOKEN_AGE;
            break;
        }
        break;
    case 4:
        switch (h2o_tolower(name[3])) {
        case 'e':
            if (h2o__lcstris_core(name, "dat", 3) )
                return H2O_TOKEN_DATE;
            break;
        case 'g':
            if (h2o__lcstris_core(name, "eta", 3) )
                return H2O_TOKEN_ETAG;
            break;
        case 'k':
            if (h2o__lcstris_core(name, "lin", 3) )
                return H2O_TOKEN_LINK;
            break;
        case 'm':
            if (h2o__lcstris_core(name, "fro", 3) )
                return H2O_TOKEN_FROM;
            break;
        case 't':
            if (h2o__lcstris_core(name, "hos", 3) )
                return H2O_TOKEN_HOST;
            break;
        case 'y':
            if (h2o__lcstris_core(name, "var", 3) )
                return H2O_TOKEN_VARY;
            break;
        }
        break;
    case 5:
        switch (h2o_tolower(name[4])) {
        case 'e':
            if (h2o__lcstris_core(name, "rang", 4) )
                return H2O_TOKEN_RANGE;
            break;
        case 'h':
            if (h2o__lcstris_core(name, ":pat", 4) )
                return H2O_TOKEN_PATH;
            break;
        case 'w':
            if (h2o__lcstris_core(name, "allo", 4) )
                return H2O_TOKEN_ALLOW;
            break;
        }
        break;
    case 6:
        switch (h2o_tolower(name[5])) {
        case 'e':
            if (h2o__lcstris_core(name, "cooki", 5) )
                return H2O_TOKEN_COOKIE;
            break;
        case 'r':
            if (h2o__lcstris_core(name, "serve", 5) )
                return H2O_TOKEN_SERVER;
            break;
        case 't':
            if (h2o__lcstris_core(name, "accep", 5) )
                return H2O_TOKEN_ACCEPT;
            if (h2o__lcstris_core(name, "expec", 5) )
                return H2O_TOKEN_EXPECT;
            break;
        }
        break;
    case 7:
        switch (h2o_tolower(name[6])) {
        case 'd':
            if (h2o__lcstris_core(name, ":metho", 6) )
                return H2O_TOKEN_METHOD;
            break;
        case 'e':
            if (h2o__lcstris_core(name, ":schem", 6) )
                return H2O_TOKEN_SCHEME;
            if (h2o__lcstris_core(name, "upgrad", 6) )
                return H2O_TOKEN_UPGRADE;
            break;
        case 'h':
            if (h2o__lcstris_core(name, "refres", 6) )
                return H2O_TOKEN_REFRESH;
            break;
        case 'r':
            if (h2o__lcstris_core(name, "refere", 6) )
                return H2O_TOKEN_REFERER;
            break;
        case 's':
            if (h2o__lcstris_core(name, ":statu", 6) )
                return H2O_TOKEN_STATUS;
            if (h2o__lcstris_core(name, "expire", 6) )
                return H2O_TOKEN_EXPIRES;
            break;
        }
        break;
    case 8:
        switch (h2o_tolower(name[7])) {
        case 'e':
            if (h2o__lcstris_core(name, "if-rang", 7) )
                return H2O_TOKEN_IF_RANGE;
            break;
        case 'h':
            if (h2o__lcstris_core(name, "if-matc", 7) )
                return H2O_TOKEN_IF_MATCH;
            break;
        case 'n':
            if (h2o__lcstris_core(name, "locatio", 7) )
                return H2O_TOKEN_LOCATION;
            break;
        }
        break;
    case 10:
        switch (h2o_tolower(name[9])) {
        case 'e':
            if (h2o__lcstris_core(name, "keep-aliv", 9) )
                return H2O_TOKEN_KEEP_ALIVE;
            if (h2o__lcstris_core(name, "set-cooki", 9) )
                return H2O_TOKEN_SET_COOKIE;
            break;
        case 'n':
            if (h2o__lcstris_core(name, "connectio", 9) )
                return H2O_TOKEN_CONNECTION;
            break;
        case 't':
            if (h2o__lcstris_core(name, "user-agen", 9) )
                return H2O_TOKEN_USER_AGENT;
            break;
        case 'y':
            if (h2o__lcstris_core(name, ":authorit", 9) )
                return H2O_TOKEN_AUTHORITY;
            break;
        }
        break;
    case 11:
        switch (h2o_tolower(name[10])) {
        case 'r':
            if (h2o__lcstris_core(name, "retry-afte", 10) )
                return H2O_TOKEN_RETRY_AFTER;
            break;
        }
        break;
    case 12:
        switch (h2o_tolower(name[11])) {
        case 'e':
            if (h2o__lcstris_core(name, "content-typ", 11) )
                return H2O_TOKEN_CONTENT_TYPE;
            break;
        case 's':
            if (h2o__lcstris_core(name, "max-forward", 11) )
                return H2O_TOKEN_MAX_FORWARDS;
            break;
        }
        break;
    case 13:
        switch (h2o_tolower(name[12])) {
        case 'd':
            if (h2o__lcstris_core(name, "last-modifie", 12) )
                return H2O_TOKEN_LAST_MODIFIED;
            break;
        case 'e':
            if (h2o__lcstris_core(name, "content-rang", 12) )
                return H2O_TOKEN_CONTENT_RANGE;
            break;
        case 'h':
            if (h2o__lcstris_core(name, "if-none-matc", 12) )
                return H2O_TOKEN_IF_NONE_MATCH;
            break;
        case 'l':
            if (h2o__lcstris_core(name, "cache-contro", 12) )
                return H2O_TOKEN_CACHE_CONTROL;
            if (h2o__lcstris_core(name, "x-reproxy-ur", 12) )
                return H2O_TOKEN_X_REPROXY_URL;
            break;
        case 'n':
            if (h2o__lcstris_core(name, "authorizatio", 12) )
                return H2O_TOKEN_AUTHORIZATION;
            break;
        case 's':
            if (h2o__lcstris_core(name, "accept-range", 12) )
                return H2O_TOKEN_ACCEPT_RANGES;
            break;
        }
        break;
    case 14:
        switch (h2o_tolower(name[13])) {
        case 'h':
            if (h2o__lcstris_core(name, "content-lengt", 13) )
                return H2O_TOKEN_CONTENT_LENGTH;
            break;
        case 's':
            if (h2o__lcstris_core(name, "http2-setting", 13) )
                return H2O_TOKEN_HTTP2_SETTINGS;
            break;
        case 't':
            if (h2o__lcstris_core(name, "accept-charse", 13) )
                return H2O_TOKEN_ACCEPT_CHARSET;
            break;
        }
        break;
    case 15:
        switch (h2o_tolower(name[14])) {
        case 'e':
            if (h2o__lcstris_core(name, "accept-languag", 14) )
                return H2O_TOKEN_ACCEPT_LANGUAGE;
            break;
        case 'g':
            if (h2o__lcstris_core(name, "accept-encodin", 14) )
                return H2O_TOKEN_ACCEPT_ENCODING;
            break;
        case 'r':
            if (h2o__lcstris_core(name, "x-forwarded-fo", 14) )
                return H2O_TOKEN_X_FORWARDED_FOR;
            break;
        }
        break;
    case 16:
        switch (h2o_tolower(name[15])) {
        case 'e':
            if (h2o__lcstris_core(name, "content-languag", 15) )
                return H2O_TOKEN_CONTENT_LANGUAGE;
            if (h2o__lcstris_core(name, "www-authenticat", 15) )
                return H2O_TOKEN_WWW_AUTHENTICATE;
            break;
        case 'g':
            if (h2o__lcstris_core(name, "content-encodin", 15) )
                return H2O_TOKEN_CONTENT_ENCODING;
            break;
        case 'n':
            if (h2o__lcstris_core(name, "content-locatio", 15) )
                return H2O_TOKEN_CONTENT_LOCATION;
            break;
        }
        break;
    case 17:
        switch (h2o_tolower(name[16])) {
        case 'e':
            if (h2o__lcstris_core(name, "if-modified-sinc", 16) )
                return H2O_TOKEN_IF_MODIFIED_SINCE;
            break;
        case 'g':
            if (h2o__lcstris_core(name, "transfer-encodin", 16) )
                return H2O_TOKEN_TRANSFER_ENCODING;
            break;
        }
        break;
    case 18:
        switch (h2o_tolower(name[17])) {
        case 'e':
            if (h2o__lcstris_core(name, "proxy-authenticat", 17) )
                return H2O_TOKEN_PROXY_AUTHENTICATE;
            break;
        }
        break;
    case 19:
        switch (h2o_tolower(name[18])) {
        case 'e':
            if (h2o__lcstris_core(name, "if-unmodified-sinc", 18) )
                return H2O_TOKEN_IF_UNMODIFIED_SINCE;
            break;
        case 'n':
            if (h2o__lcstris_core(name, "content-dispositio", 18) )
                return H2O_TOKEN_CONTENT_DISPOSITION;
            if (h2o__lcstris_core(name, "proxy-authorizatio", 18) )
                return H2O_TOKEN_PROXY_AUTHORIZATION;
            break;
        }
        break;
    case 25:
        switch (h2o_tolower(name[24])) {
        case 'y':
            if (h2o__lcstris_core(name, "strict-transport-securit", 24) )
                return H2O_TOKEN_STRICT_TRANSPORT_SECURITY;
            break;
        }
        break;
    case 27:
        switch (h2o_tolower(name[26])) {
        case 'n':
            if (h2o__lcstris_core(name, "access-control-allow-origi", 26) )
                return H2O_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN;
            break;
        }
        break;
    }

    return NULL;
}
