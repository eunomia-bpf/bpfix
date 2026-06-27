#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_FILE_NAME_LENGTH 128
#define LOG_DIR "/my/prefix"
#define LEN_LOG_DIR sizeof(LOG_DIR)

int matchPrefix(char str[MAX_FILE_NAME_LENGTH]) __attribute__((noinline));

int matchPrefix(char str[MAX_FILE_NAME_LENGTH])
{
	for (int i = 0; i < LEN_LOG_DIR; i++) {
		char ch1 = LOG_DIR[i];
		char ch2;

		if (ch1 == '\0')
			return 0;

		ch2 = str[i];
		if (ch2 == '\0')
			return -1;
		if (ch1 != ch2)
			return -2;
	}

	return -3;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int syscall_enter_open(struct trace_event_raw_sys_enter *ctx)
{
	char filename[MAX_FILE_NAME_LENGTH] = {};
	const char *name = (const char *)ctx->args[1];

	bpf_probe_read_user(filename, sizeof(filename), name);
	if (matchPrefix(filename) != 0)
		return 0;

	return 1;
}

char LICENSE[] SEC("license") = "GPL";
