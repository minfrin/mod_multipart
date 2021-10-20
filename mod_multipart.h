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

/**
 * @file mod_multipart.h
 * @brief Multipart filters and buckets.
 *
 * @defgroup MOD_MULTIPART mod_multipart
 * @ingroup  APACHE_MODS
 * @{
 */

#ifndef MOD_MULTIPART_H_
#define MOD_MULTIPART_H_


#include <apr_buckets.h>
//#include <apr_encode.h>
//#include <apr_escape.h>
//#include <apr_hash.h>
//#include <apr_lib.h>
//#include <apr_strings.h>

#include "httpd.h"
//#include "http_config.h"
//#include "http_core.h"
//#include "http_log.h"
//#include "http_protocol.h"
//#include "http_request.h"
//#include "util_script.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct multipart_t {
    /** The pool for this part */
    apr_pool_t *pool;
    /** The multipart/subtype used by this part */
    const char *subtype;
    /** The boundary string used by this part.
     */
    char    *boundary;
    /** The length of the boundary */
    apr_size_t  boundary_len;
    /** The headers of the boundary */
    apr_table_t *headers;
    /** Nesting level of the parts */
    int level;
    /** Number of parts using this memory */
    int refcount;
} multipart_t;

typedef struct part_t {
    /** The pool for this part */
    apr_pool_t *pool;
    /** The headers of this part */
    apr_table_t *headers;
    /** The content type, if present */
    const char *ct;
    /** The content type boundary, if present */
    const char *ct_boundary;
    /** The content type charset, if present */
    const char *ct_charset;
    /** The content type encoding, if present */
    const char *cte;
    /** The content disposition, if present */
    const char *dsp;
    /** The disposition filename, if present */
    const char *dsp_filename;
    /** The disposition creation-date, if present */
    const char *dsp_create;
    /** The disposition modification-date, if present */
    const char *dsp_mod;
    /** The disposition read-date, if present */
    const char *dsp_read;
    /** The disposition size, if present */
    const char *dsp_size;
    /** The disposition name, if present */
    const char *dsp_name;
} part_t;

/**
 * The MULTIPART bucket type.  This bucket represents the metadata of and start
 * of a part in a multipart message. If this bucket is still available when the
 * pool is cleared, the metadata is cleared.
 *
 * The content of the part follows this bucket as regular buckets, and ends at
 * the next MULTIPART bucket, or EOS, whichever is seen first.
 */
AP_DECLARE_DATA extern const apr_bucket_type_t ap_bucket_type_multipart;

/**
 * Determine if a bucket is a MULTIPART bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define AP_BUCKET_IS_MULTIPART(e)        ((e)->type == &ap_bucket_type_multipart)

/**
 * Make the bucket passed in a MULTIPART bucket
 * @param b The bucket to make into an MULTIPART bucket
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_multipart_make(apr_bucket *b, multipart_t *multipart, part_t *part);

/**
 * Create a bucket referring to multipart metadata.
 *
 * @param list The freelist from which this bucket should be allocated
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_multipart_create(apr_bucket_alloc_t *list, multipart_t *multipart,
        part_t *part);

/**
 * A bucket referring to the start of a multipart part.
 */
typedef struct ap_bucket_multipart {
    /** Number of buckets using this memory */
    apr_bucket_refcount  refcount;
    /** The content of the multipart */
    multipart_t *multipart;
    /** The content of the part */
    part_t *part;
} ap_bucket_multipart;


#ifdef __cplusplus
}
#endif

#endif /* MOD_MULTIPART_H_ */
/** @} */
