/* Mess with various libdb in various glibcs is something...
 * Crooked hands of hackers can result in amazing results making
 * incompatibility at all the levels without any reasons.
 *
 * The simplest trick which I was able to invent is to write fake
 * db.h including db_185.h and adding -I/usr/include/db3 to CFLAGS.
 * Looks ugly but compiles everywhere.
 */

#include <db_185.h>
