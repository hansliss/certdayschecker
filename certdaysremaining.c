#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>

#define BUFSIZE 32768

#define min(a, b) (((a) < (b))?(a):(b))

void usage(char *progname) {
  fprintf(stderr, "Usage: %s -h <host> [-p <port>] [-H (set TLS hostname)]\n", progname);
}

typedef struct readlinebuf_s {
  SSL *ssl;
  unsigned char buf[BUFSIZE];
  int startptr, endptr;
} *readline_h;

readline_h ssl_readline_init(SSL *ssl) {
  readline_h tmph = (readline_h)malloc(sizeof(struct readlinebuf_s));
  tmph->ssl = ssl;
  tmph->startptr = 0;
  tmph->endptr = 0;
  return tmph;
}

int ssl_readline_stop(readline_h *h, unsigned char *buf, int bufsize) {
  int s;
  if (!(*h))
    return 0;
  s = (*h)->endptr - (*h)->startptr;
  if (bufsize >= 0 && s > bufsize)
    s = bufsize;
  if (buf != NULL && s > 0 && bufsize > 0) {
    memcpy(buf, (*h)->buf + (*h)->startptr, s);
  }
  free(*h);
  return s;
}

char *ssl_read_line(readline_h h, int timeout) {
  int p, op=0, len, ready=0, r;
  static char linebuf[BUFSIZE];
  if (!h)
    return NULL;
  linebuf[0]='\0';
  alarm(timeout);
  while (!ready) {
    if (h->startptr >= h->endptr) {
      h->startptr=0;
      if ((r=SSL_read(h->ssl, h->buf, sizeof(h->buf)))<=0) {
	switch (SSL_get_error(h->ssl, r)) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
	  alarm(0);
	  if (!strlen(linebuf))
	    return NULL;
	  else
	    return linebuf;
	case SSL_ERROR_WANT_X509_LOOKUP:
	  fprintf(stderr, "Server demands authentication. Giving up.\n");
	  alarm(0);
	  return NULL;
	case SSL_ERROR_SYSCALL:
	  fprintf(stderr, "I/O Error. Giving up.\n");
	  alarm(0);
	  return NULL;
	case SSL_ERROR_SSL:
	  fprintf(stderr, "SSL library error. Giving up.\n");
	  alarm(0);
	  return NULL;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	  h->endptr=0;
	  break;
	}
      } else {
	h->endptr = r;
      }
    }
    p=h->startptr;
    while (p < h->endptr && !strchr("\r\n", h->buf[p]))
      p++;
    len=min(BUFSIZE - op - 1, p - h->startptr);
    memcpy(&(linebuf[op]), &(h->buf[h->startptr]), len);
    op+=len;
    linebuf[op]='\0';
    h->startptr += len;
    if (h->startptr < (BUFSIZE-1) &&
	h->buf[h->startptr] == '\r' &&
	h->buf[h->startptr+1]=='\n')
      h->startptr++;
    h->startptr++;
    if ((p < h->endptr) || (op >= BUFSIZE-1))
      ready=1;
  }
  alarm(0);
  return linebuf;
}

int ssl_read_buf(readline_h h, char *buf, int bufsize, int timeout) {
  int op=0, len, ready=0, r;
  if (!h)
    return -1;
  alarm(timeout);
  while (!ready) {
    if (h->startptr >= h->endptr) {
      h->startptr=0;
      if ((r=SSL_read(h->ssl, h->buf, sizeof(h->buf)))<=0) {
	switch (SSL_get_error(h->ssl, r)) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
	  alarm(0);
	  return op;
	case SSL_ERROR_WANT_X509_LOOKUP:
	  fprintf(stderr, "Server demands authentication. Giving up.\n");
	  alarm(0);
	  return -1;
	case SSL_ERROR_SYSCALL:
	  fprintf(stderr, "I/O Error. Giving up.\n");
	  alarm(0);
	  return -1;
	case SSL_ERROR_SSL:
	  fprintf(stderr, "SSL library error. Giving up.\n");
	  alarm(0);
	  return -1;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	  h->endptr=0;
	  break;
	}
      } else {
	h->endptr = r;
      }
    }
    len=min(bufsize - op, h->endptr - h->startptr);
    memcpy(&(buf[op]), &(h->buf[h->startptr]), len);
    op+=len;
    h->startptr += len;
    if (op >= bufsize)
      ready=1;
  }
  alarm(0);
  return op;
}

time_t ASN1_GENERALIZEDTIME_2ilb(ASN1_GENERALIZEDTIME *tm) {
  char strtime[30] ;
  time_t test = (time_t) 0;  int i ;
  if (tm->length != 15) return (time_t)-1;

  for (i = ( sizeof(time_t)*8-2) ; i>=0; i--) {           
    test += (time_t)(1 << i) ;
    strftime(strtime, 16, "%Y%m%d%H%M%SZ",gmtime(&test));
    if (strncmp((char *)tm->data,strtime,15) < 0) 
      test -= (time_t)(1 << i) ;
  } 

  return test;
}

int main(int argc, char *argv[]) {
  static char server[BUFSIZE];
  BIO *conn;
  
  SSL_CTX *my_ssl_context;
  SSL *myssl;
  X509 *peer_cert;

  int ret, r, o;
  char *host=NULL;
  char *port="443";
  int set_tls_hostname=0;

  while ((o=getopt(argc, argv, "h:p:H"))!=-1) {
    switch (o) {
    case 'h':
      host=optarg;
      break;
    case 'p':
      port=optarg;
      break;
    case 'H':
      set_tls_hostname=1;
      break;
    default:
      usage(argv[0]);
      return -1;
    }
  }
  if (!host || (optind < argc)) {
    usage(argv[0]);
    return -1;
  }

  SSL_load_error_strings();
  SSL_library_init();

  if (!(my_ssl_context=SSL_CTX_new(SSLv23_client_method()))) {
    fprintf(stderr,"SSL_CTX_new failed\n");
    return -2;
  }

  if (!(myssl=SSL_new(my_ssl_context))) {
    fprintf(stderr,"SSL_new() failed\n");
    return -3;
  }

  sprintf(server, "%s:%s", host, port);
  conn = BIO_new_connect(server);
  if (!conn) {
    fprintf(stderr, "Error creating connection BIO\n");
  }
  BIO_set_nbio(conn,0);
  if (BIO_do_connect(conn) <= 0) {
    fprintf(stderr, "Error connecting to server\n");
  }
  SSL_set_bio(myssl, conn, conn);

  if (set_tls_hostname) {
    if (!SSL_set_tlsext_host_name(myssl, host)) {
      fprintf(stderr, "SSL_set_tlsext_host_name() failed\n");
      return -8;
    }
  }

  if ((ret=SSL_connect(myssl))!=1) {
    fprintf(stderr,"SSL_connect() returned %d: %s: %s\n", ret, ERR_error_string(ERR_get_error(), NULL), ERR_error_string(SSL_get_error(myssl, ret), NULL));
    return -7;
  }


  if ((peer_cert=SSL_get_peer_certificate(myssl))) {
    ASN1_GENERALIZEDTIME *agt = NULL;
    const ASN1_TIME *at = X509_get0_notAfter(peer_cert);
    ASN1_TIME_to_generalizedtime(at, &agt);
    time_t endtime=ASN1_GENERALIZEDTIME_2ilb(agt);
    time_t now=time(NULL);
    long remainingdays = (endtime - now) / 86400;
    printf("%ld\n", remainingdays);
  } else {
    fprintf(stderr, "No certificate\n");
    printf("-1\n");
  }

  r=SSL_shutdown(myssl);
  if (r != 0 && r!=1)
    {
      fprintf(stderr,"SSL_shutdown() failed: return code %d\n", r);
      return -8;
    }
  SSL_free(myssl);
  SSL_CTX_free(my_ssl_context);
  return 0;
}
