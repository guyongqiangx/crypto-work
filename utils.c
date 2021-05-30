#include <stdio.h>
#include "utils.h"

#define DUMP_LINE_SIZE 16
int print_buffer(const void *buf, size_t len)
{
	size_t i = 0;
	for (i=0; i<len; i++)
	{
		if (i%DUMP_LINE_SIZE == 0)
		{
			if (sizeof(size_t) == 8)
				printf("%04lX:", i);
			else /* if (sizeof(size_t) == 4) */
				printf("%04X:", i);
		}

		printf(" %02x", ((char *)buf)[i]);

		if (i%DUMP_LINE_SIZE == (DUMP_LINE_SIZE-1))
			printf("\n");
	}

    if (i%DUMP_LINE_SIZE != (DUMP_LINE_SIZE-1))
	    printf("\n");

	return 0;
}

