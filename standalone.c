#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main()
{
	size_t buf_size = 16, buf_used = 0;
	uint8_t *buf = NULL;

	do // read the file passed through stdin into buf
	{
		buf_size *= 2;
		buf = (uint8_t*) realloc(buf, buf_size);
		if (buf == NULL)
		{
			perror("allocation failed");
			exit(EXIT_FAILURE);
		}

		const size_t bytes_read = fread(buf + buf_used, 1, buf_size - buf_used, stdin);
		buf_used += bytes_read;
		if (ferror(stdin))
		{
			fprintf(stderr, "error reading from stdin\n");
			exit(EXIT_FAILURE);
		}
	} while (!feof(stdin));

	printf("Read %lu bytes from stdin\n", buf_used);
	LLVMFuzzerTestOneInput(buf, buf_used);
	printf("Execution successful\n");
	free(buf);
}
