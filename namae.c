/*
    async-oriented rewrite of my tiny dns client.

    this code is meant to be copy-pasted as needed, the main
    function at the bottom shows example usage with async
    sockets.

    the core dns packet builder/parser should be compatible
    with no-libc project as long as you provide a strcmp and
    type aliases that match stdint.

    -----------------------------------------------------------

    API info:

    all decode* functions return -1 if there is not enough
    data available, and they will all require the number of
    bytes available (cb_p) in the buffer pointed by p.

    all decode* functions except for dns_decode_all return
    the number of bytes consumed.

    all encode* functions return the number of bytes written.

    encode* functions don't do bounds checking, you are
    expected to allocate a buffer big enough in advance.
    this is unsafe, but good enough for non-arbitrary input
    (such as resolving a hardcoded host in a program)

    none of the utilities provided here dynamically allocate
    any memory. all allocation is done by the caller, such
    as the example at the bottom.

    decode* functions trust the dns server to behave
    correctly according to the standard. I don't think there
    are security holes, but if garbage data is received
    it's very possible that it will read random memory and
    crash.

    commonly used functions you should read:

        dns_encode_hdr
        dns_encode_question
        dns_decode_all

    -----------------------------------------------------------
    this is free and unencumbered software released into the
    public domain, check out the attached UNLICENSE.
*/

#define NAMAE_VER "namae-async v1.1"

/* big endian integer packing/unpacking utils */

int32_t
be_encode2(uint8_t* p, uint16_t v)
{
    uint8_t const* s = p;
    *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)(v & 0x00FF);
    return p - s;
}

int32_t
be_decode2(uint8_t const* p, int32_t cb_p, uint16_t* v)
{
    uint8_t const* s = p;

    if (cb_p < 2) {
        return -1;
    }

    *v = *p++ << 8;
    *v |= *p++;
    return p - s;
}

int32_t
be_decode4(uint8_t const* p, int32_t cb_p, uint32_t* v)
{
    uint8_t const* s = p;
    int32_t n;

    n = be_decode2(p, cb_p, (uint16_t*)v + 1);
    if (n == -1) {
        return -1;
    }
    p += n;
    cb_p -= n;

    n = be_decode2(p, cb_p, (uint16_t*)v);
    if (n ==  -1) {
        return -1;
    }
    p += n;
    cb_p -= n;

    return p - s;
}

/* ------------------------------------------------------------- */

#define DNS_MAX_STR 63

/* len will be truncated to DNS_MAX_STR if higher */
int32_t
dns_encode_str(uint8_t* p, char const* str, uint8_t len)
{
    uint8_t const* s = p;
    len &= DNS_MAX_STR;

    *p++ = len;

    for (; len; --len) {
        *p++ = (uint8_t)*str++;
    }

    return p - s;
}

/*
    does not handle string pointers/offsets.

    if the server is behaving correctly, str doesn't need to
    be larger than DNS_MAX_STR.

    if you want maximum crash safety, you can make it 256
    bytes.
*/
int32_t
dns_decode_str(uint8_t const* p, int32_t cb_p, char* str)
{
    uint8_t const* s = p;
    uint8_t len;

    if (cb_p < 1) {
        return -1;
    }

    len = *p++;

    if (cb_p < len) {
        return -1;
    }

    for (; len; --len) {
        *str++ = (char)*p++;
    }

    *str++ = 0;

    return p - s;
}

/* ------------------------------------------------------------- */

/* DNS error codes, these are encoded into the dns header */

#define RCODE_OK       0
#define RCODE_EFMT     1
#define RCODE_ESERV    2
#define RCODE_ENAME    3
#define RCODE_EIMPL    4
#define RCODE_EREFUSED 5

char const*
rcode(uint8_t code)
{
    switch (code)
    {
        case RCODE_EFMT:
            return "Format error: the name server was unable to "
                   "interpret the query";
        case RCODE_ESERV:
            return "Server failure: The name server was unable to "
                   "process this query due to a problem with the "
                   "name server";
        case RCODE_ENAME:
            return "Name error: the domain name referenced in the "
                   "query does not exist";
        case RCODE_EIMPL:
            return "Not implemented: the name server does not "
                   "support the requested kind of query";
        case RCODE_EREFUSED:
            return "Refused: the name server refuses to perform "
                   "the specified operation for policy reasons";
    }

    return "Unknown error";
}

/* ------------------------------------------------------------- */

/*
    Section 4.1.1 of https://www.ietf.org/rfc/rfc1035.txt

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | <- mask
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

#define QR_QUERY       0x0000
#define QR_RESP        0x8000 /* 1 0000 0 0 0 0 000 0000 */
#define OPCODE_QUERY   0x0000
#define OPCODE_STATUS  0x1000 /* 0 0010 0 0 0 0 000 0000 */
#define DNS_RD         0x0100 /* 0 0000 0 0 1 0 000 0000 */
#define DNS_AA         0x0400 /* 0 0000 1 0 0 0 000 0000 */
#define RCODE_MASK     0x000F /* 0 0000 0 0 0 0 000 1111 */

struct dns_hdr
{
    uint16_t id;       /* unique id (i just use pid) */
    uint16_t mask;
    uint16_t qd_count; /* number of questions */
    uint16_t an_count; /* number of answers */
    uint16_t ns_count; /* number of authority records */
    uint16_t ar_count; /* number of additional records */
};

int32_t
dns_encode_hdr(uint8_t* p, struct dns_hdr const* hdr)
{
    uint8_t const* s = p;

    p += be_encode2(p, hdr->id);
    p += be_encode2(p, hdr->mask);
    p += be_encode2(p, hdr->qd_count);
    p += be_encode2(p, hdr->an_count);
    p += be_encode2(p, hdr->ns_count);
    p += be_encode2(p, hdr->ar_count);

    return p - s;
}

int32_t
dns_decode_hdr(uint8_t const* p, int32_t cb_p, struct dns_hdr* hdr)
{
    int32_t n;
    uint8_t const* s = p;

#define d2(v)                       \
    n = be_decode2(p, cb_p, v);     \
    if (n == -1) {                  \
        return -1;                  \
    }                               \
    p += n;                         \
    cb_p -= n;

    d2(&hdr->id);
    d2(&hdr->mask);
    d2(&hdr->qd_count);
    d2(&hdr->an_count);
    d2(&hdr->ns_count);
    d2(&hdr->ar_count);

#undef d2

    return p - s;
}

/* ------------------------------------------------------------- */

#define DNS_TYPE_A 1
#define DNS_CLASS_IN 1

/*
     qname: the requested hostname, such as google.com
     qtype: record type (only DNS_TYPE_A is implemented right now)
    qclass: DNS_CLASS_IN for the internet, other values are not
            implemented
*/
int32_t
dns_encode_question(
    uint8_t* p,
    char const* qname,
    uint16_t qtype,
    uint16_t qclass)
{
    uint8_t const* s = p;
    char const* label = qname;

    for (; 1; ++label)
    {
        char c = *label;

        if (c != '.' && c) {
            continue;
        }

        p += dns_encode_str(p, qname, label - qname);
        qname = label + 1;

        if (!c) {
            break;
        }
    }

    *p++ = 0;

    p += be_encode2(p, qtype);
    p += be_encode2(p, qclass);

    return p - s;
}

/* ------------------------------------------------------------- */

/*
    Section 4.1.4 of https://www.ietf.org/rfc/rfc1035.txt

    To avoid duplicate strings, an entire domain name or a list of
    labels at the end of a domain name is replaced with a pointer
    to a prior occurance of the same name.

    The pointer takes the form of a two octet sequence:

        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        | 1  1|                OFFSET                   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    The first two bits are ones. This allows a pointer to be
    distinguished from a label, since the label must begin with two
    zero bits because labels are restricted to 63 octets or less.
*/

#define DNS_MAX_HOST 0xFF
#define DNS_STR_POINTER 0xC0

/*
    decodes an entire hostname, such as google.com
    handles string pointers along the way

             p: points to the beginning of the name in the packet
          cb_p: number of bytes left from p to the end of the buffer
         qname: expected to be of size DNS_MAX_HOST
    data_begin: points to the beginning of the entire dns packet
*/
int32_t
dns_decode_name(
    uint8_t const* p,
    int32_t cb_p,
    char* qname,
    uint8_t const* data_begin)
{
    int32_t n;
    uint8_t const* s = p;

    if ((*p & DNS_STR_POINTER) == DNS_STR_POINTER)
    {
        /* a pointer basically redirects the parsing of the entire
           name to another location in the packet */
        uint16_t offset;
        uint8_t const* ptr;

        n = be_decode2(p, cb_p, &offset);
        if (n == -1) {
            return -1;
        }
        p += n;
        cb_p -= n;

        offset &= ~(DNS_STR_POINTER << 8);

        ptr = data_begin + offset;
        cb_p += p - ptr;

        if (dns_decode_name(ptr, cb_p, qname, data_begin) == -1) {
            return -1;
        }

        return p - s;
    }

    while (p - s + *p < DNS_MAX_HOST - 1)
    {
        n = dns_decode_str(p, cb_p, qname);
        if (n == -1) {
            return -1;
        }
        p += n;
        cb_p -= n;

        if (!*p) {
            break;
        }

        for (; *qname; ++qname);
        *qname++ = '.';
    }

    for (; cb_p && *p; ++p, --cb_p);
    /* skip rest in case of truncation */

    return ++p - s;
}

/*
     qtype: will store the question type
    qclass: will store the question class
*/
int32_t
dns_decode_question(
    uint8_t const* p,
    int32_t cb_p,
    char* qname,
    uint16_t* qtype,
    uint16_t* qclass,
    uint8_t const* data_begin)
{
    int32_t n;
    uint8_t const* s = p;

    n = dns_decode_name(p, cb_p, qname, data_begin);
    if (n == -1) {
        return -1;
    }
    p += n;
    cb_p -= n;

    n = be_decode2(p, cb_p, qtype);
    if (n == -1) {
        return -1;
    }
    p += n;
    cb_p -= n;

    n = be_decode2(p, cb_p, qclass);
    if (n == -1) {
        return -1;
    }
    p += n;
    cb_p -= n;

    return p - s;
}

struct dns_resource
{
    char* name;         /* hostname, such as google.com */
    uint16_t type;      /* record type, such as DNS_TYPE_A */
    uint16_t class;     /* class, such as DNS_CLASS_IN */
    uint32_t ttl;       /* how long it should be cached (secs) */
    uint16_t rd_length; /* length of data in bytes */
    void const* data;   /* for an A record, it contains the ipv4 */
};

/*
    res->name is expected to be set to a buffer of size DNS_MAX_HOST.
    res->data will point to data in p, and will only be valid as
    long as p is valid
*/
int32_t
dns_decode_resource(
    uint8_t const* p,
    int32_t cb_p,
    struct dns_resource* res,
    uint8_t const* data_begin)
{
    int32_t n;
    uint8_t const* s = p;

    n = dns_decode_question(
        p,
        cb_p,
        res->name,
        &res->type,
        &res->class,
        data_begin
    );

    if (n == -1) {
        return -1;
    }

    p += n;
    cb_p -= n;

    n = be_decode4(p, cb_p, &res->ttl);
    if (n == -1) {
        return -1;
    }
    p += n;
    cb_p -= n;

    n = be_decode2(p, cb_p, &res->rd_length);
    if (n == -1) {
        return -1;
    }
    p += n;
    cb_p -= n;

    if (cb_p < (int32_t)res->rd_length) {
        return -1;
    }

    res->data = p;
    p += res->rd_length;

    return p - s;
}

/* all possible errors that dns_decode_all can return */
#define DNS_EAGAIN   -1
#define DNS_EID      -2
#define DNS_ENOTRESP -3
#define DNS_ERCODE   -4
#define DNS_EQCOUNT  -5
#define DNS_EHOST    -6
#define DNS_ETYPE    -7
#define DNS_ECLASS   -8
#define DNS_EA       -9

char const*
dns_errstr(int32_t err)
{
    if (err >= 0) {
        return "no error";
    }

    switch (err)
    {
        case DNS_EAGAIN:
            return "data is incomplete, call me again "
                   "when you have more";

        case DNS_EID:
            return "request id mismatch";

        case DNS_ENOTRESP:
            return "not a dns response";

        case DNS_ERCODE:
            return "dns error, check header rcode for "
                   "more information";

        case DNS_EQCOUNT:
            return "question count mismatch";

        case DNS_EHOST:
            return "hostname mismatch";

        case DNS_ETYPE:
            return "query type mismatch";

        case DNS_ECLASS:
            return "query class mismatch";

        case DNS_EA:
            return "malformed A record";
    }

    return "unknown error";
}

/*
    decodes a dns response. only A records are error checked.

    if resources is null, resources won't be decoded but the number
    of resources will still be returned so the caller can allocate
    memory and call again. in this case, max_resources is also
    ignored.

    NOTE: the caller must preallocate each resource's name buffer
    NOTE: it is assumed that the dns question that triggered this
          response used the pid as the id. this will be checked
          and will throw errors if it doesn't match.

                p: beginning of the dns response packet
             cb_p: number of bytes available in p
             host: the hostname to resolve (such as google.com)
              hdr: will store the decoded dns header
        resources: array that will store the decoded records
    max_resources: maximum number of records to store in resources
*/
int32_t
dns_decode_all(
    uint8_t const* p,
    int32_t cb_p,
    char const* host,
    struct dns_hdr* hdr,
    struct dns_resource* resources,
    uint16_t max_resources)
{
    uint8_t const* start = p;
    char namebuf[DNS_MAX_HOST];
    int32_t n;
    uint16_t i;
    uint16_t nresources;
    uint16_t qtype, qclass;

    n = dns_decode_hdr(p, cb_p, hdr);
    if (n == -1) {
        return DNS_EAGAIN;
    }
    p += n;
    cb_p -= n;

    if (hdr->id != os_getpid()) {
        return DNS_EID;
    }

    if (!(hdr->mask & QR_RESP)) {
        return DNS_ENOTRESP;
    }

    if ((hdr->mask & RCODE_MASK) != RCODE_OK) {
        return DNS_ERCODE;
    }

    if (hdr->qd_count != 1) {
        return DNS_EQCOUNT;
    }

    n = dns_decode_question(
        p, cb_p,
        namebuf,
        &qtype, &qclass,
        start
    );

    if (n ==  -1) {
        return DNS_EAGAIN;
    }
    p += n;
    cb_p -= n;

    if (strcmp(namebuf, host)) {
        return DNS_EHOST;
    }

    if (qtype != DNS_TYPE_A) {
        return DNS_ETYPE;
    }

    if (qclass != DNS_CLASS_IN) {
        return DNS_ECLASS;
    }

    nresources = hdr->an_count + hdr->ns_count + hdr->ar_count;

    if (!resources) {
        goto exit;
    }

    nresources = min(max_resources, nresources);

    for (i = 0; i < nresources; ++i)
    {
        struct dns_resource* r;

        r = &resources[i];
        r->name = namebuf;

        n = dns_decode_resource(p, cb_p, r, start);
        if (n == -1) {
            return DNS_EAGAIN;
        }
        p += n;
        cb_p -= n;

        switch (r->type)
        {
            case DNS_TYPE_A:
                if (r->rd_length != 4) {
                    return DNS_EA;
                }
                break;
        }
    }

exit:
    return (int32_t)nresources;
}

/* ------------------------------------------------------------- */
/*                   EXAMPLE USAGE STARTS HERE                   */
/* ------------------------------------------------------------- */
#define BUFSIZE 0xFFFF
#define MAX_RESOURCES 16
#define POLL_DELAY 1
#define TIMEOUT 5 /* seconds */

#ifdef NAMAE_DEBUG
#define dbgprintf fprintf
#define dbgfflush fflush
#else
#define dbgprintf(...)
#define dbgfflush(x)
#endif

internalfn
void
error(char const* msg)
{
    fprintf(stderr, msg);

    if (os_err() != OS_ERROR_NONE && os_err() != EAGAIN)
    {
        char buf[128];
        os_errstr(buf, sizeof(buf));
        fprintf(stderr, ": %s", buf);
    }

    fprintf(stderr, "\n");
}

struct memory
{
    uint8_t buf[BUFSIZE];
    struct dns_resource resources[MAX_RESOURCES];
    char names[MAX_RESOURCES][DNS_MAX_HOST];
};

internalfn
int
namae_main(int argc, char* argv[])
{
    int code = 0;

    sock_t fd;
    struct memory* mem;
    int64_t lasttime; /* used in timeouts */

    /* used by query and response */
    uint8_t* p;
    struct dns_hdr hdr;

    /* used by response */
    int32_t i;
    int32_t nresources;

    /* number of bytes written/read */
    int32_t n;

    /* ----------------------------------------------------- */

    if (argc < 2)
    {
        fprintf(stderr, NAMAE_VER "\n\n");
        fprintf(stderr, "Usage: %s domain\n", argv[0]);
        return 1;
    }

    /* ----------------------------------------------------- */

#define die(msg) \
    error(msg); \
    return 1;
                                   /* just to reduce clutter */
#define die_cleanup(msg) \
    error(msg); \
    code = 1; \
    goto cleanup;

    /* ----------------------------------------------------- */

    /* do all big allocations now so we don't fail later */
    mem = os_malloc(sizeof(struct memory));
    if (!mem) {
        die("not enough memory to start up")
    }

    /* set up name buffers for the resources array */
    for (i = 0; i < MAX_RESOURCES; ++i)
    {
        mem->resources[i].name =
            (char*)mem->names[i];
    }

    /* ----------------------------------------------------- */

    fd = udp_sock();
    if (fd == OS_INVALID_SOCKET) {
        die("socket creation failed")
    }

    if (sock_block(fd, 0) < 0) {
        die_cleanup("failed to make socket non-blocking")
    }

    /* connect to google dns */
    if (os_connect(fd, "8.8.8.8", 53) < 0)
    {
        if (os_err() != EINPROGRESS) {
            die_cleanup("connection failed immediately")
        }

        dbgprintf(stderr, "connecting");
        lasttime = os_ntime_mono();

        /* poll the socket every POLL_DELAY milliseconds
           until it's writable (connected) */

        while (!sock_writable(fd, POLL_DELAY))
        {
            /* time out after TIMEOUT seconds */
            if (os_ntime_mono() - lasttime > TIMEOUT * 1e+9) {
                die_cleanup("timed out")
            }

            dbgprintf(stderr, ".");
            dbgfflush(stderr);
        }

        dbgprintf(stderr, "connected\n");
    }

    else {
        /* on some platforms it just succeeds instantly */
        dbgprintf(stderr, "connected immediately\n");
    }

    /* ----------------------------------------------------- */

    memset(&hdr, 0, sizeof(struct dns_hdr));

    /* unique id. dns_decode_all expects pid, so use pid */
    hdr.id = (uint16_t)os_getpid();

    /* query flag set, query opcode, recursion desired */
    hdr.mask = QR_QUERY | OPCODE_QUERY | DNS_RD;
    hdr.qd_count = 1; /* number of questions */

    /* pack everything into the buffer */
    p = mem->buf;
    p += dns_encode_hdr(p, &hdr);
    p += dns_encode_question(
        p,
        argv[1],     /* hostname (such as google.com) */
        DNS_TYPE_A,  /* ask for A record (ipv4) */
        DNS_CLASS_IN /* internet class */
    );

    /* ----------------------------------------------------- */

    dbgprintf(stderr, "sending..");
    lasttime = os_ntime_mono();

    /* poll every POLL_DELAY millisecs until the entire buffer
       is written */
    for (n = 0; n < p - mem->buf; )
    {
        int32_t written;

        if (os_ntime_mono() - lasttime > TIMEOUT * 1e+9) {
            die_cleanup("timed out")
        }

        written =
            sock_write(fd, mem->buf + n, p - mem->buf - n);

        if (written < 0) {
            die_cleanup("write failed")
        }

        n += written;

        dbgprintf(stderr, ".");
        dbgfflush(stderr);

        /* we have to manually sleep unlike before */
        os_sleep(POLL_DELAY);
    }

    dbgprintf(stderr, "sent\n");

    /* ----------------------------------------------------- */

    dbgprintf(stderr, "reading..");
    lasttime = os_ntime_mono();

    for (n = 0; ; )
    {
        int32_t nread;

        if (os_ntime_mono() - lasttime > TIMEOUT * 1e+9) {
            die_cleanup("timed out")
        }

        nread = sock_read(fd, mem->buf + n, BUFSIZE - n);

        if (nread < 0)
        {
            /* async read can fail if no data is available
               yet (EAGAIN), in which case we just have
               to keep polling */

            if (os_err() != EAGAIN) {
                die_cleanup("read failed")
            } else {
                nread = 0;
            }
        }

        n += nread;

        /* --------------------------------------------- */

        /* try decoding a dns response from what we have
           so far. if it's incomplete, dns_decode_all
           will return DNS_EAGAIN */

        nresources =
            dns_decode_all(
                mem->buf, n,
                argv[1],
                &hdr,
                mem->resources, MAX_RESOURCES
            );

        if (nresources >= 0) {
            /* we got all the data we needed */
            break;
        }

        if (nresources != DNS_EAGAIN)
        {
            /* dns_decode_all failed */

            if (nresources == DNS_ERCODE) {
                /* standard dns errors */
                die_cleanup(rcode(hdr.mask & RCODE_MASK));
            } else {
                /* dns_decode_all specific errors */
                die_cleanup(dns_errstr(nresources));
            }
        }

        /* incomplete, keep polling for more data */

        /* --------------------------------------------- */

        if (n >= BUFSIZE) {
            die_cleanup("read buffer full")
            break;
        }

        dbgprintf(stderr, ".");
        dbgfflush(stderr);

        os_sleep(POLL_DELAY);
    }

    dbgprintf(stderr, "%d bytes\n", n);

    /* ----------------------------------------------------- */

cleanup:
    sock_close(fd);

    if (code) {
        return code;
    }

    /* we got the answer, print the results */

    for (i = 0; i < nresources; ++i)
    {
        struct dns_resource *r;
        uint8_t const* pdata;

        r = &mem->resources[i];
        dbgprintf(stderr, "%s: ", r->name);

        pdata = r->data;

        switch (r->type)
        {
            case DNS_TYPE_A:
                printf(
                    "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n",
                    pdata[0], pdata[1], pdata[2], pdata[3]
                );
                break;
        }
    }

    return 0;
}

