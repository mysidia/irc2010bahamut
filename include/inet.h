/*
 * Copyright (c) 1983 Regents of the University of California. All
 * rights reserved.
 * 
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its
 * contributors'' in the documentation or other materials provided with
 * the distribution and in all advertising materials mentioning
 * features or use of this software. Neither the name of the University
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission. THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.
 * 
 * @(#)inet.h   5.4 (Berkeley) 6/1/90
 */

/* $Id: inet.h,v 1.1 2000/07/15 21:59:32 mysidia Exp $ */

/*
 * External definitions for functions in inet(3) 
 */
#include "config.h"		/* for system definitions */

#ifdef	__alpha
#define	__u_l	unsigned int
#else
#define	__u_l	unsigned long
#endif

#ifdef __STDC__
extern __u_l inet_addr(char *);
extern char *inet_ntoa(char *);
extern __u_l inet_makeaddr(int, int);
extern __u_l inet_network(char *);
extern __u_l inet_lnaof(struct in_addr);
extern __u_l inet_netof(struct in_addr);

#else
extern __u_l inet_addr();
extern char *inet_ntoa();

extern __u_l inet_makeaddr();

#endif
extern __u_l inet_network();
extern __u_l inet_lnaof();
extern __u_l inet_netof();

#undef __u_l
