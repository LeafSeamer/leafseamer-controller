#include <stdio.h>
#include <sys/timex.h>

int main(void) {
  struct timex reading = {0};
  const int state = adjtimex(&reading);
  if (state < 0) {
    perror("adjtimex");
    return 1;
  }
  puts(state == TIME_OK && !(reading.status & (STA_UNSYNC | STA_CLOCKERR)) ?
       "synchronized" : "unsynchronized");
  return 0;
}
