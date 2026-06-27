#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define VERIFIER_LOG_SIZE (16U * 1024U * 1024U)

static void json_write_string(FILE *out, const char *value)
{
	const unsigned char *p;

	if (!value) {
		fputs("null", out);
		return;
	}

	fputc('"', out);
	for (p = (const unsigned char *)value; *p != '\0'; p++) {
		switch (*p) {
		case '\\':
			fputs("\\\\", out);
			break;
		case '"':
			fputs("\\\"", out);
			break;
		case '\b':
			fputs("\\b", out);
			break;
		case '\f':
			fputs("\\f", out);
			break;
		case '\n':
			fputs("\\n", out);
			break;
		case '\r':
			fputs("\\r", out);
			break;
		case '\t':
			fputs("\\t", out);
			break;
		default:
			if (*p < 0x20) {
				fprintf(out, "\\u%04x", *p);
			} else {
				fputc(*p, out);
			}
			break;
		}
	}
	fputc('"', out);
}

static void print_usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s <bpf-object> <program-name>\n", argv0);
}

static void print_result(
	const char *object_path,
	const char *program_name,
	const char *section_name,
	bool load_ok,
	int error_code,
	const char *error_message,
	const char *verifier_log)
{
	fputs("{\"object_path\":", stdout);
	json_write_string(stdout, object_path);
	fputs(",\"program_name\":", stdout);
	json_write_string(stdout, program_name);
	fputs(",\"section_name\":", stdout);
	json_write_string(stdout, section_name);
	fputs(",\"load_ok\":", stdout);
	fputs(load_ok ? "true" : "false", stdout);
	fputs(",\"error_code\":", stdout);
	fprintf(stdout, "%d", error_code);
	fputs(",\"error_message\":", stdout);
	json_write_string(stdout, error_message);
	fputs(",\"verifier_log\":", stdout);
	json_write_string(stdout, verifier_log);
	fputs("}\n", stdout);
}

static void format_error(int err, char *buf, size_t buf_sz)
{
	if (buf_sz == 0)
		return;

	if (err == 0) {
		snprintf(buf, buf_sz, "success");
		return;
	}

	if (libbpf_strerror(err, buf, buf_sz) == 0 && buf[0] != '\0')
		return;

	snprintf(buf, buf_sz, "error %d", err);
}

int main(int argc, char **argv)
{
	const char *object_path;
	const char *target_program_name;
	struct bpf_object_open_opts open_opts;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_program *target_prog = NULL;
	char *verifier_log = NULL;
	const char *section_name = NULL;
	char error_message[256];
	int err = 0;

	if (argc != 3) {
		print_usage(argv[0]);
		return 2;
	}

	object_path = argv[1];
	target_program_name = argv[2];

	libbpf_set_print(NULL);

	verifier_log = calloc(1, VERIFIER_LOG_SIZE);
	if (!verifier_log) {
		format_error(-ENOMEM, error_message, sizeof(error_message));
		print_result(object_path, target_program_name, NULL, false, -ENOMEM,
			     error_message, NULL);
		return 1;
	}

	memset(&open_opts, 0, sizeof(open_opts));
	open_opts.sz = sizeof(open_opts);
	obj = bpf_object__open_file(object_path, &open_opts);
	err = libbpf_get_error(obj);
	if (err) {
		obj = NULL;
		format_error(err, error_message, sizeof(error_message));
		print_result(object_path, target_program_name, NULL, false, err,
			     error_message, verifier_log[0] ? verifier_log : NULL);
		free(verifier_log);
		return 1;
	}

	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);
		bool is_target = name && strcmp(name, target_program_name) == 0;

		err = bpf_program__set_autoload(prog, is_target);
		if (err) {
			format_error(err, error_message, sizeof(error_message));
			print_result(object_path, target_program_name, NULL, false, err,
				     error_message, verifier_log[0] ? verifier_log : NULL);
			bpf_object__close(obj);
			free(verifier_log);
			return 1;
		}

		if (is_target)
			target_prog = prog;
	}

	if (!target_prog) {
		err = -ENOENT;
		format_error(err, error_message, sizeof(error_message));
		print_result(object_path, target_program_name, NULL, false, err,
			     error_message, NULL);
		bpf_object__close(obj);
		free(verifier_log);
		return 1;
	}

	section_name = bpf_program__section_name(target_prog);

	err = bpf_program__set_log_buf(target_prog, verifier_log, VERIFIER_LOG_SIZE);
	if (err) {
		format_error(err, error_message, sizeof(error_message));
		print_result(object_path, target_program_name, section_name, false, err,
			     error_message, verifier_log[0] ? verifier_log : NULL);
		bpf_object__close(obj);
		free(verifier_log);
		return 1;
	}

	err = bpf_program__set_log_level(target_prog, 2);
	if (err) {
		format_error(err, error_message, sizeof(error_message));
		print_result(object_path, target_program_name, section_name, false, err,
			     error_message, verifier_log[0] ? verifier_log : NULL);
		bpf_object__close(obj);
		free(verifier_log);
		return 1;
	}

	err = bpf_object__load(obj);
	format_error(err, error_message, sizeof(error_message));
	print_result(object_path, target_program_name, section_name, err == 0, err,
		     error_message, verifier_log[0] ? verifier_log : NULL);

	bpf_object__close(obj);
	free(verifier_log);
	return err == 0 ? 0 : 1;
}
