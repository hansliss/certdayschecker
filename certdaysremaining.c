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
  fprintf(stderr, "Usage: %s -h <host> [-p <port>] [-c <filename for cert listing>]\n", progname);
  fprintf(stderr, "\t[-P <pem filename for cert dump>] [-C (dump entire certificate chain)]\n");
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
  int i;
  X509_EXTENSION *ex;
  STACK_OF(GENERAL_NAME) *alt;
  STACK_OF(X509) *cert_chain;
  int n;
  unsigned char *sn;
  int sl;
  GENERAL_NAME *gn;

  X509_NAME *xn;
  char buf[8192];

  BIO *text_outfile=NULL;
  BIO *outfile=NULL;

  int ret;

  int r;


  int o;
  char *host=NULL;
  char *port="443";
  char *certfilename=NULL;
  char *pemfilename=NULL;
  int savechain=0;

  while ((o=getopt(argc, argv, "h:p:c:CP:u:K:"))!=-1) {
    switch (o) {
    case 'h':
      host=optarg;
      break;
    case 'p':
      port=optarg;
      break;
    case 'c':
      certfilename=optarg;
      break;
    case 'C':
      savechain=1;
      break;
    case 'P':
      pemfilename=optarg;
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

  if ((ret=SSL_connect(myssl))!=1) {
    fprintf(stderr,"SSL_connect() returned %d: %s: %s\n", ret, ERR_error_string(ERR_get_error(), NULL), ERR_error_string(SSL_get_error(myssl, ret), NULL));
    return -7;
  }

  if (certfilename) {
    text_outfile=BIO_new(BIO_s_file());
    if (BIO_write_filename(text_outfile, certfilename) <= 0) {
      perror(certfilename);
      BIO_free(text_outfile);
      text_outfile=NULL;
    }
  }

  if (pemfilename) {
    outfile=BIO_new(BIO_s_file());

    if (BIO_write_filename(outfile, pemfilename) <= 0) {
      perror(pemfilename);
      BIO_free(outfile);
      outfile=NULL;
    }
  }

  if ((peer_cert=SSL_get_peer_certificate(myssl))) {
    ASN1_GENERALIZEDTIME *agt;
    ASN1_TIME_to_generalizedtime(peer_cert->cert_info->validity->notAfter, &agt);
    time_t endtime=ASN1_GENERALIZEDTIME_2ilb(agt);
    time_t now=time(NULL);
    long remainingdays = (endtime - now) / 86400;
    printf("%ld\n", remainingdays);

    if (!savechain) {
      if (text_outfile)
	X509_print(text_outfile, peer_cert);
      if (outfile)
	PEM_write_bio_X509(outfile,peer_cert);
    }
    else {
      if ((cert_chain=SSL_get_peer_cert_chain(myssl))!=NULL) {
	for (i=0; i<sk_X509_num(cert_chain); i++) {
	  if (text_outfile) {
	    xn=X509_get_subject_name(sk_X509_value(cert_chain,i));
	    if (X509_NAME_get_text_by_NID(xn, NID_commonName, buf, sizeof(buf)) != -1)
	      BIO_printf(text_outfile, "## CN=%s\n", buf);
	    else
	      BIO_printf(text_outfile, "## CN=<unknown>\n");
	    X509_print(text_outfile, sk_X509_value(cert_chain,i));
	  }
	  if (outfile)
	    PEM_write_bio_X509(outfile, sk_X509_value(cert_chain,i));
	}
      }
    }

    xn=X509_get_subject_name(peer_cert);
    if (X509_NAME_get_text_by_NID(xn, NID_commonName, buf, sizeof(buf)) != -1) {
      // printf("subject common name is \"%s\"\n", buf);
    } else {
      printf("X509_NAME_get_text_by_NID() failed\n");
    }
    if ((i=X509_get_ext_by_NID(peer_cert, NID_subject_alt_name, -1))>=0) {
      ex=X509_get_ext(peer_cert, i);
      if ((alt=X509V3_EXT_d2i(ex))) {
	n=sk_GENERAL_NAME_num(alt);
	for (i=0; i<n; i++) {
	  gn=sk_GENERAL_NAME_value(alt, i);
	  if (gn->type == GEN_DNS) {
	    sn=ASN1_STRING_data(gn->d.ia5);
	    sl=ASN1_STRING_length(gn->d.ia5);
	    // printf("%d: \"%s\" (%d)\n", i, sn, sl);
	  } else {
	    // printf("%d: type=%d\n", i, gn->type);
	  }
	}
	// method = X509V3_EXT_get(ex);
	// if (method) method->ext_free(alt);
      }
      else
	fprintf(stderr, "X509V3_EXT_d2i() failed.\n");
    }
    X509_free(peer_cert);
  } else
    fprintf(stderr, "SSL_get_peer_certificate() failed.\n");
  
  if (text_outfile)
    BIO_free(text_outfile);
  if (outfile)
    BIO_free(outfile);
  
  fflush(stdout);
  fflush(stderr);

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
