/*******************************************************************
 * nss-ddnss.c
 *
 * Written by Jan <goarano@gmail.com>, February 2017
 *
 * Based on 'nss-myhostname' by Lennart Poettering
 * and nss-clientha by Open Systems
 *
 * LICENSE:
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 *******************************************************************/

#include <nss.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/file.h>


char* NAME_FOLDER = "/srv/nss/ddnss/";
size_t NAME_FOLDER_SIZE = 15; /* strlen(NAME_FOLDER) */


#define ALIGN(a) (((a+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))

static inline size_t PROTO_ADDRESS_SIZE(int proto) {
        assert(proto == AF_INET || proto == AF_INET6);

        return proto == AF_INET6 ? 16 : 4;
}

enum nss_status _nss_ddnss_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp);

enum nss_status _nss_ddnss_gethostbyname2_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop);

enum nss_status _nss_ddnss_gethostbyname_r(
                const char *name,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop);

static enum nss_status get_hostent(
                const char *hn,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

    size_t l    = strlen(hn);

    /* We only check .ddnss hostnames */
    int ok = 0;
    if( l > 6 && strcmp(".ddnss", hn+l-6) == 0 ) {
        ok = 1;
    }
    if(!ok) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    char *r_addr, *r_name, *r_aliases, *r_addr_list;
    size_t alen = PROTO_ADDRESS_SIZE(af);


    /* First, fill in hostname */
    r_name = buffer;
    memcpy(r_name, hn, l+1);
    size_t idx = ALIGN(l+1);

    /* Second, create (empty) aliases array */
    r_aliases = buffer + idx;
    *(char**) r_aliases = NULL;
    idx += sizeof(char*);

    // get host file name
    char *host_file = malloc( sizeof(char) * (l+NAME_FOLDER_SIZE+1) );
    strcpy(host_file,NAME_FOLDER);
    strcpy(host_file+NAME_FOLDER_SIZE,hn);

    // read host file
    FILE *fp;
    fp = fopen(host_file , "rb");
    free(host_file);
    if( !fp ) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    flock(fileno(fp), LOCK_SH);

    char ip_char[64];

    /* copy the file into the buffer */
    size_t rn = fread( ip_char , sizeof(char), 63, fp);

    // 3 is minimal length of IP (::1)
    if( rn < 3 ) {
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    ip_char[rn] = '\0';

    flock(fileno(fp), LOCK_UN);
    fclose(fp);

    // read first word
    char* pt = ip_char;
    while(*pt && !isspace(*pt)) pt++;
    *pt = '\0';

    // convert to unsigned int
    struct sockaddr_in sa;
    unsigned int ip_uint = 0;
    int pton_res = inet_pton(af, ip_char, &(ip_uint)); // convert to uint
    if(pton_res!=1) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    /* Third, add addresses */
    r_addr = buffer + idx;
    *(unsigned int*)r_addr = ip_uint;
    idx += ALIGN(alen);

    /* Fourth, add address pointer array */
    r_addr_list = buffer + idx;
    ((char**) r_addr_list)[0] = r_addr;
    ((char**) r_addr_list)[1] = NULL;
    idx += 2*sizeof(char*);

    result->h_name = r_name;
    result->h_aliases = (char**) r_aliases;
    result->h_addrtype = af;
    result->h_length = alen;
    result->h_addr_list = (char**) r_addr_list;

    if (ttlp)
        *ttlp = 0;

    if (canonp)
        *canonp = r_name;

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ddnss_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {

    if (af == AF_UNSPEC)
        af = AF_INET;

    if (af != AF_INET && af != AF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    return get_hostent(name, af, host, buffer, buflen, errnop, h_errnop, ttlp, canonp);
}

enum nss_status _nss_ddnss_gethostbyname2_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop) {

    return _nss_ddnss_gethostbyname3_r(
                    name,
                    af,
                    host,
                    buffer, buflen,
                    errnop, h_errnop,
                    NULL,
                    NULL);
}

enum nss_status _nss_ddnss_gethostbyname_r(
                const char *name,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop) {

    return _nss_ddnss_gethostbyname3_r(
                    name,
                    AF_UNSPEC,
                    host,
                    buffer, buflen,
                    errnop, h_errnop,
                    NULL,
                    NULL);
}

