/**
 *    Copyright (C) 2021 Graham Leggett <minfrin@sharp.fm>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * mod_multipart - Apache httpd multipart parser module
 *
 * The Apache mod_multipart module provides a set of filters that
 * can parse and interpret multipart MIME content.
 */


#include <apr_encode.h>
#include <apr_escape.h>
#include <apr_hash.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include "mod_multipart.h"
//#include "http_config.h"
//#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "ap_expr.h"

module AP_MODULE_DECLARE_DATA multipart_module;

#define MULTIPART_READ_BLOCKSIZE      16384    /* used for reading input blocks */
#define DEFAULT_DEPTH                 32       /* 32 levels deep, max */

typedef struct
{
    int depth;
    int depth_set;
} multipart_config_rec;

#ifndef HAVE_APR_BRIGADE_SPLIT_BOUNDARY

#define APR_BUCKETS_STRING -1

/**
 * Split a brigade based on the provided boundary, or metadata buckets,
 * whichever are encountered first.
 *
 * If the boundary is found, all buckets prior to the boundary are passed
 * into bbOut, and APR_SUCCESS is returned.
 *
 * If a metadata bucket is found, or if the boundary is not found within
 * the limit specified by maxbytes, all prior buckets are passed into bbOut,
 * and APR_INCOMPLETE is returned.
 *
 * If the boundary is NULL or the empty string, APR_EINVAL is returned.
 *
 * If an error is encountered, the APR error code will be returned.
 *
 * @param bbOut The bucket brigade that will have the LF line appended to.
 * @param bbIn The input bucket brigade to search for a LF-line.
 * @param block The blocking mode to be used to split the line.
 * @param boundary The boundary string.
 * @param boundary_len The length of the boundary string. If set to
 *        APR_BUCKETS_STRING, the length will be calculated.
 * @param maxbytes The maximum bytes to read.
 */
apr_status_t apr_brigade_split_boundary(apr_bucket_brigade *bbOut,
                                        apr_bucket_brigade *bbIn,
                                        apr_read_type_e block,
                                        const char *boundary,
                                        apr_size_t boundary_len,
                                        apr_off_t maxbytes)
{
    apr_off_t outbytes = 0;

    if (!boundary || !boundary[0]) {
        return APR_EINVAL;
    }

    if (APR_BUCKETS_STRING == boundary_len) {
        boundary_len = strlen(boundary);
    }

    /*
     * While the call describes itself as searching for a boundary string,
     * what we actually do is search for anything that is definitely not
     * a boundary string, and allow that not-boundary data to pass through.
     *
     * If we find data that might be a boundary, we try read more data in
     * until we know for sure.
     */
    while (!APR_BRIGADE_EMPTY(bbIn)) {

        const char *pos;
        const char *str;
        apr_bucket *e, *next, *prev;
        apr_off_t inbytes = 0;
        apr_size_t len;
        apr_status_t rv;

        /* We didn't find a boundary within the maximum line length. */
        if (outbytes >= maxbytes) {
            return APR_INCOMPLETE;
        }

        e = APR_BRIGADE_FIRST(bbIn);

        /* We hit a metadata bucket, stop and let the caller handle it */
        if (APR_BUCKET_IS_METADATA(e)) {
            return APR_INCOMPLETE;
        }

        rv = apr_bucket_read(e, &str, &len, block);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        inbytes += len;

        /*
         * Fast path.
         *
         * If we have at least one boundary worth of data, do an optimised
         * substring search for the boundary, and split quickly if found.
         */
        if (len >= boundary_len) {

            apr_size_t off;
            apr_size_t leftover;

            pos = strnstr(str, boundary, len);

            /* definitely found it, we leave */
            if (pos != NULL) {

                off = pos - str;

                /* everything up to the boundary */
                if (off) {

                    apr_bucket_split(e, off);
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(bbOut, e);

                    e = APR_BRIGADE_FIRST(bbIn);
                }

                /* cut out the boundary */
                apr_bucket_split(e, boundary_len);
                apr_bucket_delete(e);

                return APR_SUCCESS;
            }

            /* any partial matches at the end? */
            leftover = boundary_len - 1;
            off = (len - leftover);

            while (leftover) {
                if (!strncmp(str + off, boundary, leftover)) {

                    if (off) {

                        apr_bucket_split(e, off);
                        APR_BUCKET_REMOVE(e);
                        APR_BRIGADE_INSERT_TAIL(bbOut, e);

                        e = APR_BRIGADE_FIRST(bbIn);
                    }

                    outbytes += off;
                    inbytes -= off;

                    goto skip;
                }
                off++;
                leftover--;
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(bbOut, e);

            outbytes += len;

            continue;

        }

        /*
         * Slow path.
         *
         * We need to read ahead at least one boundary worth of data so
         * we can search across the bucket edges.
         */
        else {

            apr_size_t off = 0;

            /* find all definite non matches */
            while (len) {
                if (!strncmp(str + off, boundary, len)) {

                    if (off) {

                        apr_bucket_split(e, off);
                        APR_BUCKET_REMOVE(e);
                        APR_BRIGADE_INSERT_TAIL(bbOut, e);

                        e = APR_BRIGADE_FIRST(bbIn);
                    }

                    inbytes -= off;

                    goto skip;
                }
                off++;
                len--;
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(bbOut, e);
            continue;

        }

        /*
         * If we reach skip, it means the bucket in e is:
         *
         * - shorter than the boundary
         * - matches the boundary up to the bucket length
         * - might match more buckets
         *
         * Read further buckets and check whether the boundary matches all
         * the way to the end. If so, we have a match. If no match, shave off
         * one byte and continue round to try again.
         */
skip:

        for (next = APR_BUCKET_NEXT(e);
                inbytes < boundary_len && next != APR_BRIGADE_SENTINEL(bbIn);
                next = APR_BUCKET_NEXT(next)) {

            const char *str;
            apr_size_t off;
            apr_size_t len;

            rv = apr_bucket_read(next, &str, &len, block);

            if (rv != APR_SUCCESS) {
                return rv;
            }

            off = boundary_len - inbytes;

            if (len > off) {

                /* not a match, bail out */
                if (strncmp(str, boundary + inbytes, off)) {
                    break;
                }

                /* a match! remove the boundary and return */
                apr_bucket_split(next, off);

                e = APR_BUCKET_NEXT(next);

                for (prev = APR_BRIGADE_FIRST(bbIn);
                        prev != e;
                        prev = APR_BRIGADE_FIRST(bbIn)) {

                    apr_bucket_delete(prev);

                }

                return APR_SUCCESS;

            }
            if (len == off) {

                /* not a match, bail out */
                if (strncmp(str, boundary + inbytes, off)) {
                    break;
                }

                /* a match! remove the boundary and return */
                e = APR_BUCKET_NEXT(next);

                for (prev = APR_BRIGADE_FIRST(bbIn);
                        prev != e;
                        prev = APR_BRIGADE_FIRST(bbIn)) {

                    apr_bucket_delete(prev);

                }

                return APR_SUCCESS;

            }
            else if (len) {

                /* not a match, bail out */
                if (strncmp(str, boundary + inbytes, len)) {
                    break;
                }

                /* still hope for a match */
                inbytes += len;
            }

        }

        /*
         * If we reach this point, the bucket e did not match the boundary
         * in the subsequent buckets.
         *
         * Bump one byte off, and loop round to search again.
         */
        apr_bucket_split(e, 1);
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bbOut, e);

        outbytes++;

    }

    return APR_INCOMPLETE;
}
#endif

/**
 * Search for a character within a string, ignoring quoted sections.
 */
static const char *ap_strnchr_quoted(const char *s, int c, apr_size_t n)
{
    int inquotes = 0;
    int incomment = 0;
    int escaped = 0;

    if (!s) {
        return NULL;
    }

    while (n && *s) {

        if (escaped) {
            escaped = 0;
        }

        else if (*s == '\\') {
            escaped = 1;
        }

        else if (*s == '"') {
            inquotes = !inquotes;
        }

        else if (*s == '(') {
            incomment++;
        }

        else if (*s == ')') {
            incomment--;
        }

        if (!inquotes && !incomment && *s == c) {
            return s;
        }

        s++;
        n--;
    };

    return NULL;
}

static const char *ap_pstrndup_quoted(apr_pool_t *a, const char *s, apr_size_t n)
{
    char *dest, *d;

    apr_size_t len = 0;
    apr_size_t off = 0;

    int inquotes = 0;
    int incomment = 0;
    int escaped = 0;

    if (!s) {
        return NULL;
    }

    while (n > off && s[off]) {

        if (escaped) {
            len++;
            off++;
            escaped = 0;
            continue;
        }

        if (s[off] == '\\') {
            escaped = 1;
            off++;
            continue;
        }

        if (s[off] == '"') {
            inquotes = !inquotes;
            off++;
            continue;
        }

        if (s[off] == '(') {
            incomment++;
            off++;
            continue;
        }

        if (s[off] == ')') {
            incomment--;
            off++;
            continue;
        }

        if (!incomment) {
            len++;
        }

        off++;
    };

    dest = d = apr_palloc(a, len + 1);

    off = 0;

    while (n > off && s[off]) {

        if (escaped) {
            escaped = 0;
            *d++ = s[off++];
            continue;
        }

        if (s[off] == '\\') {
            escaped = 1;
            off++;
            continue;
        }

        if (s[off] == '"') {
            inquotes = !inquotes;
            off++;
            continue;
        }

        if (s[off] == '(') {
            incomment++;
            off++;
            continue;
        }

        if (s[off] == ')') {
            incomment--;
            off++;
            continue;
        }

        if (!incomment) {
            *d++ = s[off++];
        }
        else {
            off++;
        }

    };

    *d = 0;

    return dest;
}

static const char *ap_header_vparse(apr_pool_t *p, const char *header,
        va_list vp)
{
    char *argk;
    const char **argv;

    const char *token;
    const char *params;
    const char *next;

    apr_size_t len;

    if (!header) {
        return NULL;
    }

    len = strlen(header);

    params = ap_strnchr_quoted(header, ';', len);
    if (!params) {
        return header;
    }
    else {
        len -= (params - header);
        header = ap_pstrndup_quoted(p, header, params - header);
    }

    do {

        argk = va_arg(vp, char *);
        if (!argk) {
            break;
        }

        argv = va_arg(vp, const char **);
        if (!argv) {
            break;
        }

        token = params;
        do {

            const char *equals;

            /* skip the semicolon from last time, and any trailing whitespace */
            while (*(++token) && apr_isspace(*token));

            next = ap_strnchr_quoted(token, ';', len - (token - params));
            if (!next) {

                apr_size_t l = strlen(token);

                /* now for the name / value pair */
                equals = ap_strnchr_quoted(token, '=', l);

                if (equals && !strncasecmp(token, argk, equals - token)) {
                    *argv = ap_pstrndup_quoted(p, equals + 1,
                            len - (equals - params) - 1);
                }

                break;
            }
            else {

                /* now for the name / value pair */
                equals = ap_strnchr_quoted(token, '=', next - token);

                if (equals && !strncasecmp(token, argk, equals - token)) {
                    *argv = ap_pstrndup_quoted(p, equals + 1, next - equals - 1);
                }

                token = next;
            }

        } while (1);

    } while (1);

    return header;
}

static const char *ap_header_parse(apr_pool_t *p, const char *header, ...)
{
    const char *h;

    va_list vp;
    va_start(vp, header);
    h = ap_header_vparse(p, header, vp);
    va_end(vp);

    return h;
}

#if 0
static const char *ap_escape_header_extension(apr_pool_t *p, const char *header)
{
    /**
     * Implement
     *
     * https://datatracker.ietf.org/doc/html/rfc2231
     * https://datatracker.ietf.org/doc/html/rfc5987
     */

// FIXME

    return header;
}
#endif

static void multipart_ref(multipart_t *mp)
{
    mp->refcount++;
}

static void multipart_unref(multipart_t *mp)
{
    mp->refcount--;
    if (!mp->refcount) {
        apr_pool_destroy(mp->pool);
    }
}

AP_DECLARE(apr_bucket *) ap_bucket_multipart_make(apr_bucket *b,
        multipart_t *multipart, part_t *part)
{
    ap_bucket_multipart *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->multipart = multipart;
    h->part = part;

    multipart_ref(multipart);

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_multipart;
    return b;
}

AP_DECLARE(apr_bucket*) ap_bucket_multipart_create(apr_bucket_alloc_t *list,
        multipart_t *multipart, part_t *part)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b = ap_bucket_multipart_make(b, multipart, part);
    return b;
}

static void multipart_bucket_destroy(void *data)
{
    ap_bucket_multipart *h = data;

    if (apr_bucket_shared_destroy(h)) {
        if (h->part) {
            apr_pool_destroy(h->part->pool);
            h->part = NULL;
        }
        if (h->multipart) {
            multipart_unref(h->multipart);
            h->multipart = NULL;
        }
        apr_bucket_free(h);
    }
}

static apr_status_t multipart_bucket_read(apr_bucket *b, const char **str,
        apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_multipart = {
    "MULTIPART", 5, APR_BUCKET_METADATA,
    multipart_bucket_destroy,
    multipart_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

typedef enum multipart_state_e {
    MULTIPART_PREAMBLE,
    MULTIPART_BOUNDARY,
    MULTIPART_HEADER,
    MULTIPART_BODY,
    MULTIPART_EPILOG
} multipart_state_e;

typedef struct multipart_ctx_t
{
    apr_bucket_brigade *in;
    apr_bucket_brigade *filtered;
    apr_bucket_brigade *out;
    apr_array_header_t *multiparts;
    multipart_t *multipart;
    part_t *part;
    apr_off_t remaining;
    multipart_state_e state;
    int seen_eos:1;
} multipart_ctx;

static apr_status_t multipart_cleanup(void *data)
{
    multipart_ctx *ctx = data;

    apr_array_pop(ctx->multiparts);

    if (ctx->multiparts->nelts) {
        ctx->multipart = APR_ARRAY_IDX(ctx->multiparts, ctx->multiparts->nelts - 1, multipart_t *);
    }
    else {
        ctx->multipart = NULL;
    }
    return APR_SUCCESS;
}

static multipart_t *multipart_push(multipart_ctx *ctx,
        const char *subtype, const char *boundary)
{
    apr_pool_t *pool;

    multipart_t **pmp;
    multipart_t *mp;

    apr_pool_create(&pool, ctx->multiparts->pool);

    mp = apr_pcalloc(pool, sizeof(multipart_t));
    mp->pool = pool;
    mp->subtype = apr_pstrdup(pool, subtype);
    mp->boundary = apr_pstrdup(pool, boundary);
    mp->boundary_len = strlen(boundary);
    mp->level = ctx->multiparts->nelts;

    pmp = apr_array_push(ctx->multiparts);
    *pmp = mp;

    apr_pool_cleanup_register(pool, ctx, multipart_cleanup,
                              apr_pool_cleanup_null);

    ctx->multipart = mp;

    return mp;
}

static void multipart_parse_headers(part_t *part, const char *key,
        const char *value)
{

    if (strncasecmp(key, "Content-", 8)) {
        return;
    }
    key += 8;

    if (!strcasecmp(key, "Type")) {

        /* https://datatracker.ietf.org/doc/html/rfc2045#section-5 */

        part->ct = ap_header_parse(part->pool, value, "boundary",
                &part->ct_boundary, "charset", &part->ct_charset, NULL);

    } else if (!strcasecmp(key, "Transfer-Encoding")) {

        /* https://datatracker.ietf.org/doc/html/rfc2045#section-6 */

        part->cte = ap_header_parse(part->pool, value, NULL);

    } else if (!strcasecmp(key, "Disposition")) {

        /* https://www.ietf.org/rfc/rfc2183.txt
         * https://datatracker.ietf.org/doc/html/rfc7578#section-4.2
         */

        part->dsp = ap_header_parse(part->pool, value, "filename",
                &part->dsp_filename, "creation-date", &part->dsp_create,
                "modification-date", &part->dsp_mod, "read-date",
                &part->dsp_read, "size", &part->dsp_size, "name",
                &part->dsp_name, NULL);

    }

}

/* This is the multipart filter */
static apr_status_t multipart_in_filter(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    apr_bucket *e, *after;
    request_rec *r = f->r;
    multipart_ctx *ctx = f->ctx;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (!ctx) {

        const char *ct;
        const char *type;
        const char *boundary;

        /*
         * Boundary is limited to 70 characters in rfc2046 section 5.1.1.
         *
         * We allocate the carriage return, line feed, first two dash
         * characters, then 70 characters, then a trailing nul.
         */
//        char subtype[256];
//        char boundary[75] = CRLF "--";

        ct = apr_table_get(r->headers_in, "Content-Type");

        /* only work on main request/no subrequests */
        if (!ap_is_initial_req(r)) {
            goto bypass;
        }

        /* multipart only, and with a boundary */
#if 0
        if (ct
                && (sscanf(ct,
                        "multipart/%250[a-z-]; boundary=\"%70[0-9a-zA-Z'()+_,./:=? -]\"",
                        subtype, boundary + 4) == 2
                        || sscanf(ct,
                                "multipart/%250[a-z-]; boundary=%70[0-9a-zA-Z'()+_,./:=?-]",
                                subtype, boundary + 4) == 2)) {
            /* ok */
        } else {
            goto bypass;
        }
#endif

        type = ap_header_parse(r->pool, ct, "boundary",
                &boundary, NULL);

        if (!type || strcasecmp(type, "multipart/form-data")) {
            goto bypass;
        }

        if (!boundary || !boundary[0]) {
// FIXME error
            goto bypass;
        }

        boundary =
                apr_pstrcat(r->pool, CRLF "--", boundary, NULL);

        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->in = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->filtered = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->out = apr_brigade_create(r->pool, f->c->bucket_alloc);

        ctx->multiparts = apr_array_make(r->pool, 1, sizeof(ap_bucket_multipart *));

        multipart_push(ctx, type + 10, boundary);

        multipart_ref(ctx->multipart);
    }

    /* if our buffer is empty, read off the network until the buffer is full */
    if (APR_BRIGADE_EMPTY(ctx->out)) {

        int rv;

        rv = ap_get_brigade(f->next, ctx->in, AP_MODE_READBYTES, block,
                MULTIPART_READ_BLOCKSIZE);

        /* if an error was received, bail out now. If the error is
          * EAGAIN and we have not yet seen an EOS, we will definitely
          * be called again, at which point we will send our buffered
          * data. Instead of sending EAGAIN, some filters return an
          * empty brigade instead when data is not yet available. In
          * this case, we drop through and pass buffered data, if any.
          */
         if (APR_STATUS_IS_EAGAIN(rv)
             || (rv == APR_SUCCESS
                 && block == APR_NONBLOCK_READ
                 && APR_BRIGADE_EMPTY(ctx->in))) {
             if (APR_BRIGADE_EMPTY(ctx->out)) {
                 return rv;
             }
             goto skip;
         }
         if (APR_SUCCESS != rv) {
             return rv;
         }

         while (1) {
             int seen_metadata = 0;

             /*
              * leading metadata buckets are passed through as is, and we
              * pass them back immediately. The EOS is detected here.
              */
             for (e = APR_BRIGADE_FIRST(ctx->in);
                  e != APR_BRIGADE_SENTINEL(ctx->in) && APR_BUCKET_IS_METADATA(e);
                  e = APR_BUCKET_NEXT(e))
             {

                 if (APR_BUCKET_IS_EOS(e)) {
                     APR_BRIGADE_CONCAT(ctx->out, ctx->in);
                     ctx->seen_eos = 1;
                     goto skip;
                 }
                 else {
                     APR_BUCKET_REMOVE(e);
                     APR_BRIGADE_INSERT_TAIL(ctx->out, e);
                 }

                 seen_metadata = 1;
             }

             if (seen_metadata) {
                 break;
             }

             if (APR_BRIGADE_EMPTY(ctx->in)) {
                 break;
             }

             /*
              * Our brigade has at least one data bucket in it, let's process
              * that bucket.
              */
             switch (ctx->state) {
             case MULTIPART_PREAMBLE: {

                 /* discard everything until the first boundary, which does
                  * not necessarily have a leading CRLF
                  */
                rv = apr_brigade_split_boundary(ctx->filtered, ctx->in, block,
                        ctx->multipart->boundary + 2,
                        ctx->multipart->boundary_len - 2,
                        MULTIPART_READ_BLOCKSIZE);

                 if (rv == APR_INCOMPLETE) {
                     /* no boundary yet, throw away the preamble so far */
                     apr_brigade_cleanup(ctx->filtered);
                     goto skip;
                 }
                 else if (rv == APR_SUCCESS) {
                     /* we found a boundary, throw away the preamble
                      * expect zero or more headers.
                      */
                     apr_brigade_cleanup(ctx->filtered);

                     /* drop through to boundary */
                     ctx->state = MULTIPART_BOUNDARY;

                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_BOUNDARY: {

                 /* If we see whitespace CRLF, headers are coming up.
                  *
                  * If we see dash dash CRLF, the epilog is coming up.
                  */

                 /* read the bit after the boundary */
                 rv = apr_brigade_split_boundary(ctx->filtered, ctx->in, block,
                         CRLF, 2, HUGE_STRING_LEN);

                 if (rv == APR_INCOMPLETE) {
                     /* no CRLF found within a reasonable distance, stream
                      * is bogus */
                     apr_brigade_cleanup(ctx->filtered);


                     // FIXME error handling

                     goto skip;
                 }
                 else if (rv == APR_SUCCESS) {

                     char header[HUGE_STRING_LEN];
                     apr_size_t len = HUGE_STRING_LEN;

                     /* the bit after the boundary */
                     apr_brigade_flatten(ctx->filtered, header, &len);

                     /* found a double dash? */
                     if (len >= 2 && !strncmp(header, "--", 2)) {

                         apr_brigade_cleanup(ctx->filtered);

                         /* drop into epilog */
                         ctx->state = MULTIPART_EPILOG;

                         continue;
                     }

                     /* found whitespace? */
                     else {

                         int off = 0;

                         while (off < len && apr_isspace(header[off++]));

                         if (off == len) {

                             apr_pool_t *pool;

                             apr_pool_create(&pool, r->pool);

                             ctx->part = apr_pcalloc(pool, sizeof(part_t));
                             ctx->part->pool = pool;
                             ctx->part->headers = apr_table_make(pool, 2);

                             /* drop into header */
                             ctx->state = MULTIPART_HEADER;

                         }

                     }


                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_HEADER: {

                 /* read a header */
                 rv = apr_brigade_split_boundary(ctx->filtered, ctx->in, block,
                         CRLF, 2, HUGE_STRING_LEN);

                 if (rv == APR_INCOMPLETE) {
                     /* header too long */
                     apr_brigade_cleanup(ctx->filtered);


                     // FIXME error handling

                     goto skip;
                 }
                 else if (rv == APR_SUCCESS) {

                     char header[HUGE_STRING_LEN];
                     apr_size_t len = HUGE_STRING_LEN;

                     /* we found a header! how exciting */
                     apr_brigade_flatten(ctx->filtered, header, &len);

                     /* parse the header */
                     if (len) {

                         const char *key;
                         char *value = memchr(header, ':', len);

                         if (value) {

                             int off = value - header;
                             key = apr_pstrndup(ctx->part->pool, header, off);
                             while (++off <= len && apr_isspace(header[off]));
                             value = apr_pstrndup(ctx->part->pool, header + off,
                                     len - off);

                             apr_table_setn(ctx->part->headers, key, value);

                             /* parse some common headers, like content type */
                             multipart_parse_headers(ctx->part, key, value);

                             apr_brigade_cleanup(ctx->filtered);

                             break;
                         }
                         else {
                             // corrupt header line

                             // FIXME error handling

                         }

                     }
                     /* empty header, next up a body */
                     else {

                         /* push a multipart bucket and return it */
                         e = ap_bucket_multipart_create(
                                 r->connection->bucket_alloc, ctx->multipart, ctx->part);
                         APR_BRIGADE_INSERT_TAIL(ctx->out, e);

                         ctx->part = NULL;

                         apr_brigade_cleanup(ctx->filtered);
                         ctx->state = MULTIPART_BODY;
                     }

                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_BODY: {

                 /* pass body downstream until the boundary */
                 rv = apr_brigade_split_boundary(ctx->out, ctx->in, block,
                         ctx->multipart->boundary, ctx->multipart->boundary_len,
                         MULTIPART_READ_BLOCKSIZE);

                 /* no boundary yet, pass down */
                 if (rv == APR_INCOMPLETE) {
                     break;
                 }

                 /* we found a boundary, pass rest of the body and expect zero
                  * or more headers.
                  */
                 else if (rv == APR_SUCCESS) {
                     ctx->state = MULTIPART_BOUNDARY;

                     /* loop round into header */
                     break;
                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_EPILOG: {

                 multipart_unref(ctx->multipart);

                 while (!APR_BRIGADE_EMPTY(ctx->in)) {
                     e = APR_BRIGADE_FIRST(ctx->in);

                     if (APR_BUCKET_IS_METADATA(e)) {
                         break;
                     }
                     else {
                         apr_bucket_delete(e);
                     }

                 }

             }
             }


        }
    }

skip:

    /* give the caller the data they asked for from the buffer */
    apr_brigade_partition(ctx->out, readbytes, &after);
    e = APR_BRIGADE_FIRST(ctx->out);
    while (e != after) {
        if (APR_BUCKET_IS_EOS(e)) {
            /* last bucket read, step out of the way */
            ap_remove_input_filter(f);
        }
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = APR_BRIGADE_FIRST(ctx->out);
    }

    return APR_SUCCESS;

bypass:
    ap_remove_input_filter(f);
    return ap_get_brigade(f->next, bb, mode, block, readbytes);

}




static void *create_multipart_dir_config(apr_pool_t *p, char *d)
{
    multipart_config_rec *conf = apr_pcalloc(p, sizeof(multipart_config_rec));

    conf->depth = DEFAULT_DEPTH;

    return conf;
}

static void *merge_multipart_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    multipart_config_rec *new = (multipart_config_rec *) apr_pcalloc(p,
            sizeof(multipart_config_rec));
    multipart_config_rec *add = (multipart_config_rec *) addv;
    multipart_config_rec *base = (multipart_config_rec *) basev;

    new->depth = (add->depth_set == 0) ? base->depth : add->depth;
    new->depth_set = add->depth_set || base->depth_set;

    return new;
}

static const char *set_depth(cmd_parms *cmd, void *dconf, const char *arg)
{
    multipart_config_rec *conf = dconf;

    conf->depth = atoi(arg);
    conf->depth_set = 1;

    return NULL;
}

static const command_rec multipart_cmds[] =
{
AP_INIT_TAKE1("MultipartDepth",
        set_depth, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to the depth at which we're willing to nest parts."),
{ NULL } };




static void register_hooks(apr_pool_t *p)
{
    ap_register_input_filter("MULTIPART", multipart_in_filter, NULL,
                              AP_FTYPE_CONTENT_SET);
}

module AP_MODULE_DECLARE_DATA multipart_module =
{
    STANDARD20_MODULE_STUFF,
    create_multipart_dir_config,  /* dir config creater */
    merge_multipart_dir_config,   /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    multipart_cmds,               /* command apr_table_t */
    register_hooks              /* register hooks */
};
