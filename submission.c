#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/uclient.h>

#include <glob.h>
#include <dlfcn.h>
#include <fcntl.h>

#include <limits.h>
#include <stdio.h>

#include "submission.h"


#define TIMEOUT_SEC	10
#define TIMEOUT_MSEC	(TIMEOUT_SEC * 1000)

static int request_progress = 0;
static struct uclient *cl;

static struct ustream_ssl_ctx *ssl_ctx;
static const struct ustream_ssl_ops *ssl_ops;

static struct uloop_timeout submission_timer;

struct uclient_header *submission_headers;
const char *submission_url;
extern char *submission_queue;
int submission_headers_num;


static void request_done(struct uclient *cl, int err_code) {
	uclient_disconnect(cl);
	request_progress = 0;
	free(submission_queue);
	submission_queue = NULL;
	uloop_timeout_set(&submission_timer, TIMEOUT_MSEC);
}

static void header_done_cb(struct uclient *cl) {
	request_done(cl, 0);
}

static void read_cb(struct uclient *cl) {
	return;
}

static int init_ustream_ssl(void) {
	void *dlh;
	glob_t gl;
	int i;

	dlh = dlopen("libustream-ssl.so", RTLD_LAZY | RTLD_LOCAL);
	if (!dlh)
		return -ENOENT;

	ssl_ops = dlsym(dlh, "ustream_ssl_ops");
	if (!ssl_ops)
		return -ENOENT;

	ssl_ctx = ssl_ops->context_new(false);

	glob("/etc/ssl/certs/*.crt", 0, NULL, &gl);
	if (!gl.gl_pathc)
		return -ENOKEY;

	for (i = 0; i < gl.gl_pathc; i++)
		ssl_ops->context_add_ca_crt_file(ssl_ctx, gl.gl_pathv[i]);

	return 0;
}

int post_url(const char *url, struct uclient_header *headers, int num_headers, char *post_data) {
	if (request_progress)
		return 0;

	static struct uclient_data d = { };
	static struct uclient_cb cb = {
		.error = request_done,
		.data_eof = header_done_cb,
		.header_done = header_done_cb,
		.data_read = read_cb,
	};
	int ret;

	if (cl) {
		uclient_free(cl);
		if (ssl_ctx)
			ssl_ops->context_free(ssl_ctx);
	}

	init_ustream_ssl();

	request_progress = 1;


	cl = uclient_new(url, NULL, &cb);
	if (!cl)
		goto err;

	if (ssl_ctx && ssl_ops)
		uclient_http_set_ssl_ctx(cl, ssl_ops, ssl_ctx, 1);

	cl->timeout_msecs = TIMEOUT_MSEC;
	cl->priv = &d;
	if (uclient_set_timeout(cl, TIMEOUT_MSEC)) {
			goto err;
	}
	ret = uclient_connect(cl);
	if (ret) {
		goto err;
	}
	if (uclient_http_set_request_type(cl, "POST")) {
		goto err;
	}
	if (uclient_http_reset_headers(cl)) {
		goto err;
	}
	if (uclient_http_set_header(cl, "Content-Type", "application/x-www-form-urlencoded")) {
		goto err;
	}
	for (int i = 0; i < num_headers; i++) {
		if (uclient_http_set_header(cl, headers[i].name, headers[i].value)) {
			goto err;
		}
	}
	uclient_write(cl, post_data, strlen(post_data));
	if (uclient_request(cl)) {
		goto err;
	}

	return 0;

err:
	request_progress = 0;
	if (cl)
		uclient_free(cl);

	return 1;
}

static void
usteer_influxdb_start_submission_cb(struct uloop_timeout *timeout)
{
	if (submission_queue == NULL) {
		uloop_timeout_set(&submission_timer, TIMEOUT_MSEC);
		return;
	}
	post_url(submission_url, submission_headers, submission_headers_num, submission_queue);
}


void usteer_influxdb_start_submission(const char *url, struct uclient_header *headers, int num_headers) {
	submission_headers = headers;
	submission_headers_num = num_headers;
	submission_url = url;
	submission_timer.cb = usteer_influxdb_start_submission_cb;
	uloop_timeout_set(&submission_timer, 1);
}