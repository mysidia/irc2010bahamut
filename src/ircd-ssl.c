/*
 *   IRC - Internet Relay Chat, src/crypto.c
 *   Cryptographic functions for ircd
 *
 *   Copyright (C) 2000 Mysidia
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __LINT__
static char rcsid[] = "$Id: ircd-ssl.c,v 1.3 2001/02/11 06:36:09 mysidia Exp $";
#endif

#include <ssl.h>

SSL_CTX *my_ctx = NULL;

void get_server_key();

void initialize_ssl()
{
   SSL_METHOD *ssl3method;

   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_all_algorithms();
   ssl3method = SSLv3_server_method();
   if (!ssl3method) {
       fprintf(stderr, "Error establishing SSL method.\n");
       exit(-1);
   }
   if (!(my_ctx = SSL_CTX_new(ssl3method))) {
       fprintf(stderr, "Error establishing SSL context.\n");
       exit(-1);
   }

   SSL_CTX_use_RSAPrivateKey_file(my_ctx, "./server.key", 0);
   SSL_CTX_use_certificate_file(my_ctx, "./server.crt", 0);

   /* get_server_key(); */
}

#if 0
void get_server_key()
{
    PKCS12 *p12;
    FILE *fp = fopen("./server.key", "r");
    EVP_PKEY *pkey;
    X509 *cert;

    if (fp && (p12 = d2i_PKCS12_fp(fp, NULL))) {
        PKCS12_parse(p12, "foo", &pkey, &cert, NULL);
        PKCS12_free(p12);
    }
    else if (!fp && (fp = fopen("./ircd.pem", "w")))
    {
        p12 = *PKCS12_create("foo", "server", &pkey, &cert,
                             NULL, 0, 0,  0, 0, 0);
        i2d_PKCS12_fp(fp, p12);
        PKCS12_free(p12);
    }
    else {
       printf("UHOH!");
       exit(0);
    }
}
#endif

