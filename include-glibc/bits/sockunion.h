
/* I cannot describe, how I laughed, when saw, that now sys/socket.h
   includes ALL OF networking include files. 8)8)8)

   Bravo! Aah, they forgot sockaddr_ll, sockaddr_pkt and sockaddr_nl...
   Not a big problem, we only start the way to single UNIVERSAL include file:

   #include <GNU-Gnu_is_Not_Unix.h>.

   Jokes apart, it is full crap. Removed.
   --ANK

 */

/* Union of all sockaddr types (required by IPv6 Basic API).  This is
   somewhat evil.  */
/* 8)8) Well, ipngwg really does strange things sometimes, but
   not in such extent! It is removed long ago --ANK
 */

union sockaddr_union
  {
    struct sockaddr sa;
    char __maxsize[128];
  };
