/* Tiny shim over valgrind memcheck client requests.
 * ct_mark_undefined(p, n) marks n bytes at p as uninitialised ("secret"); under
 * valgrind, any branch/address derived from those bytes is then reported. */
#include <stddef.h>
#include <valgrind/memcheck.h>

void ct_mark_undefined(void *p, size_t n) {
    (void)VALGRIND_MAKE_MEM_UNDEFINED(p, n);
}
