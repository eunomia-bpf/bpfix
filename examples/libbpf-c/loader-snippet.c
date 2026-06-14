// Minimal libbpf-C pattern for preserving a verifier log for BPFix.
//
// This is a snippet, not a complete loader. Keep your existing map setup,
// attach logic, and cleanup. The important part is storing the kernel verifier
// log before handing it to `bpfix`.

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

int load_with_bpfix_log(const char *object_path)
{
    static char verifier_log[1 << 20];
    struct bpf_object *obj;
    int err;

    LIBBPF_OPTS(bpf_object_open_opts, open_opts,
        .kernel_log_buf = verifier_log,
        .kernel_log_size = sizeof(verifier_log),
        .kernel_log_level = 2,
    );

    obj = bpf_object__open_file(object_path, &open_opts);
    if (!obj) {
        fprintf(stderr, "failed to open %s: %s\n", object_path, strerror(errno));
        return -errno;
    }

    err = bpf_object__load(obj);
    if (err) {
        FILE *fp = fopen("verifier.log", "w");
        if (fp) {
            fputs(verifier_log, fp);
            fclose(fp);
        }
        fprintf(stderr, "verifier rejected %s; run: bpfix verifier.log\n",
                object_path);
    }

    bpf_object__close(obj);
    return err;
}
