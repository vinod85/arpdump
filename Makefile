PROG    =       arpdump
CFLAGS  +=      -Werror -Wall -Wextra
SRCS    =       arpdump.c
LDFLAGS +=      
NO_MAN  =       sorry
CLEANFILES = $(PROGS) *~ $(OBJECTS)
.include <bsd.prog.mk>

