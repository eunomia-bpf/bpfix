#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_FILE_NAME 32

static __always_inline int ends_with09(char needle[],
				       const char haystack[],
				       int haystack_length)
{
	int haystack_start = haystack_length - 9;
	volatile char ch;

	if (haystack_start < 0)
		return 0;

	ch = haystack[haystack_start];
	return ch == needle[0];
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int stack_read_repro(void *ctx)
{
	char needle[9] = "12345678";
	char buffer[MAX_FILE_NAME] = {};
	int length = bpf_get_prandom_u32();

	if (ends_with09(needle, buffer, length))
		return 1;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
