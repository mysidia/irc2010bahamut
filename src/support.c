
/************************************************************************
 *   IRC - Internet Relay Chat, src/support.c
 *   Copyright (C) 1990, 1991 Armin Gruner
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

/* $Id: support.c,v 1.1 2000/07/15 21:59:29 mysidia Exp $ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"

#define FOREVER for(;;)

extern int  errno;		/*

				 * ...seems that errno.h doesn't define this
				 * * everywhere 
				 */
extern void outofmemory();

#if !defined( HAVE_STRTOKEN )
/*
 * *  strtoken.c --   walk through a string of tokens, using a set *
 * f separators *                       argv 9/90 *
 * 
 *      $Id: support.c,v 1.1 2000/07/15 21:59:29 mysidia Exp $
 */

char       *
strtoken(save, str, fs)
     char      **save;
     char       *str, *fs;
{
char       *pos = *save;	/*

				 * keep last position across calls 
				 */
char   *tmp;

   if (str)
      pos = str;		/*
				 * new string scan 
				 */

   while (pos && *pos && strchr(fs, *pos) != NULL)
      pos++;			/*
				 * skip leading separators 
				 */

   if (!pos || !*pos)
      return (pos = *save = NULL);	/*
					 * string contains only sep's 
					 */

   tmp = pos;			/*
				 * now, keep position of the token 
				 */

   while (*pos && strchr(fs, *pos) == NULL)
      pos++;			/*
				 * skip content of the token 
				 */

   if (*pos)
      *pos++ = '\0';		/*
				 * remove first sep after the token 
				 */
   else
      pos = NULL;		/*
				 * end of string 
				 */

   *save = pos;
   return (tmp);
}
#endif /*
        * !HAVE_STRTOKEN 
        */

#if !defined( HAVE_STRTOK )
/*
 * * NOT encouraged to use!
 */

char       *
strtok(str, fs)
     char       *str, *fs;
{
static char *pos;

   return strtoken(&pos, str, fs);
}
#endif /*
        * !HAVE_STRTOK 
        */

#if !defined( HAVE_STRERROR )
/*
 * *  strerror - return an appropriate system error string to a given
 * errno *
 * 
 *                 argv 11/90 * $Id: support.c,v 1.2 1998/07/06
 * 00:48:50 cvs Exp $
 */

char       *
strerror(err_no)
     int         err_no;
{
#if !defined(__FreeBSD__) && !defined(__NetBSD__)
extern char *sys_errlist[];	/*

				 * Sigh... hopefully on all systems 
				 */
extern int  sys_nerr;

#endif
static char buff[40];
char       *errp;

   errp = (err_no > sys_nerr ? (char *) NULL : sys_errlist[err_no]);

   if (errp == (char *) NULL) {
      errp = buff;
      (void) sprintf(errp, "Unknown Error %d", err_no);
   }
   return errp;
}
#endif /*
        * !HAVE_STRERROR 
        */
/*
 * *  inetntoa  --    changed name to remove collision possibility
 * and *                        so behaviour is gaurunteed to take a
 * pointer arg. *                       -avalon 23/11/92 *
 * inet_ntoa -- returned the dotted notation of a given *
 * nternet number (some ULTRIX don't have this) *
 * rgv 11/90). *        inet_ntoa --    its broken on some Ultrix/Dynix
 * too. -avalon *       $Id: support.c,v 1.2 1998/07/06 00:48:50 cvs
 * Exp $
 */

char       *
inetntoa(in)
     char       *in;
{
static char buf[16];
u_char *s = (u_char *) in;
int     a, b, c, d;

   a = (int) *s++;
   b = (int) *s++;
   c = (int) *s++;
   d = (int) *s++;
   (void) ircsprintf(buf, "%d.%d.%d.%d", a, b, c, d);

   return buf;
}
#if !defined( HAVE_INET_NETOF )
/*
 * *  inet_netof --   return the net portion of an internet number *
 * rgv 11/90 *  $Id: support.c,v 1.1 2000/07/15 21:59:29 mysidia Exp $ *
 * 
 */

int
inet_netof(in)
     struct in_addr in;
{
int         addr = in.s_net;

   if (addr & 0x80 == 0)
      return ((int) in.s_net);

   if (addr & 0x40 == 0)
      return ((int) in.s_net * 256 + in.s_host);

   return ((int) in.s_net * 256 + in.s_host * 256 + in.s_lh);
}

#endif /*
        * !HAVE_INET_NETOF 
        */

char       *
MyMalloc(size_t x)
{
char       *ret = (char *) malloc(x);

   if (!ret) {
      outofmemory();
   }
   return ret;
}

char       *
MyRealloc(char *x, size_t y)
{
   char       *ret = (char *) realloc(x, y);

   if (!ret) {
      outofmemory();
   }
   return ret;
}

/*
 * * read a string terminated by \r or \n in from a fd *
 * 
 * Created: Sat Dec 12 06:29:58 EST 1992 by avalon * Returns: * 0 - EOF *
 * -1 - error on read *     >0 - number of bytes returned (<=num) *
 * After opening a fd, it is necessary to init dgets() by calling it as *
 * dgets(x,y,0); * to mark the buffer as being empty.
 * 
 * cleaned up by - Dianora aug 7 1997 *argh*
 */
int
dgets(int fd, char *buf, int num)
{
   static char dgbuf[8192];
   static char *head = dgbuf, *tail = dgbuf;
   char *s, *t;
   int n, nr;

   /*
    * * Sanity checks.
    */
   if (head == tail)
      *head = '\0';

   if (!num) {
      head = tail = dgbuf;
      *head = '\0';
      return 0;
   }

   if (num > sizeof(dgbuf) - 1)
      num = sizeof(dgbuf) - 1;

   FOREVER
   {
      if (head > dgbuf) {
	 for (nr = tail - head, s = head, t = dgbuf; nr > 0; nr--)
	    *t++ = *s++;
	 tail = t;
	 head = dgbuf;
      }
      /*
       * * check input buffer for EOL and if present return string.
       */
      if (head < tail &&
	  ((s = strchr(head, '\n')) || (s = strchr(head, '\r'))) && s < tail) {
	 n = MIN(s - head + 1, num);	/*
					 * at least 1 byte 
					 */
	 memcpy(buf, head, n);
	 head += n;
	 if (head == tail)
	    head = tail = dgbuf;
	 return n;
      }

      if (tail - head >= num) {	/*
				 * dgets buf is big enough 
				 */
	 n = num;
	 memcpy(buf, head, n);
	 head += n;
	 if (head == tail)
	    head = tail = dgbuf;
	 return n;
      }

      n = sizeof(dgbuf) - (tail - dgbuf) - 1;
      nr = read(fd, tail, n);
      if (nr == -1) {
	 head = tail = dgbuf;
	 return -1;
      }

      if (!nr) {
	 if (tail > head) {
	    n = MIN(tail - head, num);
	    memcpy(buf, head, n);
	    head += n;
	    if (head == tail)
	       head = tail = dgbuf;
	    return n;
	 }
	 head = tail = dgbuf;
	 return 0;
      }

      tail += nr;
      *tail = '\0';

      for (t = head; (s = strchr(t, '\n'));) {
	 if ((s > head) && (s > dgbuf)) {
	    t = s - 1;
	    for (nr = 0; *t == '\\'; nr++)
	       t--;
	    if (nr & 1) {
	       t = s + 1;
	       s--;
	       nr = tail - t;
	       while (nr--)
		  *s++ = *t++;
	       tail -= 2;
	       *tail = '\0';
	    }
	    else
	       s++;
	 }
	 else
	    s++;
	 t = s;
      }
      *tail = '\0';
   }
}
