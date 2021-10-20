# mod_multipart
An Apache httpd module that parses multipart MIME content

## filter
The MULTIPART filter interprets content type matching multipart/*, parsing
the headers for each part, and then returning the parts as MULTIPART buckets
that can be parsed for further processing by other handlers and filters.

## bucket
The MULTIPART bucket contains parsed metadata about the given content. The
content of each part is passed as buckets between multipart buckets.

