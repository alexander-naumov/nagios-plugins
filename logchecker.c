/*
SNMP LogCheck

Alexander Naumov <alexander_naumov@opensuse.org>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program (see the file COPYING); if not, see
http://www.gnu.org/licenses/, or contact Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA

========= DESCRIPTION =================================

This check parses logfile (arg 2) or just a text file and tries to
find the substring (ERROR_STRING, arg 2) in it. It returns specific
value (arg 4) if substring is found or just string OK if not.
It's implemented for JIRA logs and uses its logfile date format,
but could be of course rewritten.

========= OPTIONS =====================================

time_period  - Time period in days. For example, for all evens 2
               weeks old it should be 14.
error_string - What we're looking for.
file         - Log file PATH.
return_value - 0:OK, 1:WARNINIG, 2:CRITICAL, 3:UNKNOWN

========= INSTALL =====================================

$ gcc -Wall logchecker.c -o logchecker
# chown root:root logchecker

The concept of setuid files means that if you have the setuid bit
turned on on a file, anybody executing that command (file) will
inherit the permissions of the owner of the file:

# chmod 6755 logchecker

*/

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
#define MAX_REC_LEN 128

int converter(char *string)
{
  char *end = NULL;
  errno = 0;
  long temp = strtol(string, &end, 10);

  if (end != string && errno != ERANGE && temp >= INT_MIN && temp <= INT_MAX)
    return (int)temp;
  else {
    perror("Error printed by perror");
    exit(EXIT_FAILURE);
  }
}  


int main(int argc, char *argv[])
{
  FILE *stream;
  char *line = NULL;
  char ret_str[4096];
  size_t len = 0;
  ssize_t nread;
  int time_diff, ret = 0;
  char date_str[30];
  bool sswitch = false;

  if (argc != 5) {
    fprintf(stderr, "Usage: %s <time_period> <error_string> <file> <return_value>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  int time_period = converter(argv[1]);

  stream = fopen(argv[3], "r");
  if (stream == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  time_t now;
  struct tm* now_time, log_time;
  time (&now);
  now_time = localtime (&now);
  time_t t1 = mktime(now_time);

  while ((nread = getline(&line, &len, stream)) != -1) {
    if (strstr(line, argv[2])) {
      memcpy(date_str, line, 29);
      memset(&log_time, 0, sizeof(struct tm));

      strptime(date_str, "%a %b %d %H:%M:%S %Z %Y", &log_time);
      time_t t2 = mktime(&log_time);

      time_diff = (int)difftime(t1, t2) / 60 / 60 / 24;
      if (time_diff < time_period) {
        strcpy(ret_str, line);
        sswitch = true;
      }
    }
  }

  if (sswitch) {
    printf("%s", ret_str);
    ret = converter(argv[4]);
  }
  else
    printf("OK\n");

  free(line);
  fclose(stream);
  exit(ret);
}

