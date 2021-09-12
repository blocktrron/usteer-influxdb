#include <libubox/blobmsg_json.h>
#include <libubox/blob.h>
#include <libubox/uloop.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "ubus.h"
#include "submission.h"
#include "usteer-influxdb.h"

#define USTEER_OBJECT_NAME	"usteer"

extern struct ui_settings config;

char *submission_queue;

enum {
	USTEER_EVENT_NODE,
	USTEER_EVENT_STA,
	USTEER_EVENT_SIGNAL,
	USTEER_EVENT_REASON,
	USTEER_EVENT_THRESHOLD,
	USTEER_EVENT_SELECT_REASON,
	USTEER_EVENT_NODE_LOCAL,
	USTEER_EVENT_NODE_REMOTE,
	USTEER_EVENT_COUNT,
	__USTEER_EVENT_MAX,
};

static const struct blobmsg_policy usteer_event_policy[] = {
	[USTEER_EVENT_NODE] = { "node", BLOBMSG_TYPE_STRING },
	[USTEER_EVENT_STA] = { "sta", BLOBMSG_TYPE_STRING },
	[USTEER_EVENT_SIGNAL] = { "signal", BLOBMSG_TYPE_INT32 },
	[USTEER_EVENT_REASON] = { "reason", BLOBMSG_TYPE_STRING },
	[USTEER_EVENT_THRESHOLD] = { "threshold", BLOBMSG_TYPE_ARRAY },
	[USTEER_EVENT_SELECT_REASON] = { "select_reason", BLOBMSG_TYPE_ARRAY },
	[USTEER_EVENT_NODE_LOCAL] = { "local", BLOBMSG_TYPE_TABLE },
	[USTEER_EVENT_NODE_REMOTE] = { "remote", BLOBMSG_TYPE_TABLE },
	[USTEER_EVENT_COUNT] = { "count", BLOBMSG_TYPE_INT32 },
};

enum {
	USTEER_EVENT_NODE_STATUS_LOAD,
	USTEER_EVENT_NODE_STATUS_ASSOC,
	USTEER_EVENT_NODE_STATUS_NAME,
	USTEER_EVENT_NODE_STATUS_SIGNAL,
	USTEER_EVENT_NODE_STATUS_FREQUENCY,
	USTEER_EVENT_NODE_STATUS_BSSID,
	__USTEER_EVENT_NODE_STATUS_MAX,
};

static const struct blobmsg_policy usteer_event_node_status_policy[] = {
	[USTEER_EVENT_NODE_STATUS_LOAD] = { "load", BLOBMSG_TYPE_INT32 },
	[USTEER_EVENT_NODE_STATUS_ASSOC] = { "assoc", BLOBMSG_TYPE_INT32 },
	[USTEER_EVENT_NODE_STATUS_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[USTEER_EVENT_NODE_STATUS_SIGNAL] = { "signal", BLOBMSG_TYPE_INT32 },
	[USTEER_EVENT_NODE_STATUS_FREQUENCY] = { "frequency", BLOBMSG_TYPE_INT32 },
	[USTEER_EVENT_NODE_STATUS_BSSID] = { "bssid", BLOBMSG_TYPE_STRING },
};

#define USTEER_EVENT_SELECT_REASON_LEN	3

struct blobmsg_policy usteer_event_select_reason_policy[USTEER_EVENT_SELECT_REASON_LEN] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
};

static char *usteer_influxdb_get_submission(const char *ev_type, struct blob_attr **tb, struct blob_attr **tb_local, struct blob_attr **tb_remote, struct blob_attr **tb_select_reason) {
	unsigned long long millisecondsSinceEpoch;
	char out_buf[4096];
	char tmp_buf[64];
	struct timeval tv;
	int i;

	memset(out_buf, 0, sizeof(char) * 2048);

	if (!tb[USTEER_EVENT_SIGNAL] || !tb[USTEER_EVENT_STA])
		return NULL;

	strcpy(out_buf, ev_type);

	snprintf(tmp_buf, 64, ",host=%s", config.host);
	strcat(out_buf, tmp_buf);


	if (tb[USTEER_EVENT_NODE]) {
		strcat(out_buf, ",");
		strcat(out_buf, "local_node=");
		strcat(out_buf, blobmsg_get_string(tb[USTEER_EVENT_NODE]));
	}

	if (tb_remote[USTEER_EVENT_NODE_STATUS_NAME]) {
		strcat(out_buf, ",");
		strcat(out_buf, "remote_node=");
		strcat(out_buf, blobmsg_get_string(tb_remote[USTEER_EVENT_NODE_STATUS_NAME]));
	}

	if (tb_local[USTEER_EVENT_NODE_STATUS_BSSID]) {
		strcat(out_buf, ",");
		strcat(out_buf, "local_node_bssid=");
		strcat(out_buf, blobmsg_get_string(tb_local[USTEER_EVENT_NODE_STATUS_BSSID]));
	}

	if (tb_remote[USTEER_EVENT_NODE_STATUS_BSSID]) {
		strcat(out_buf, ",");
		strcat(out_buf, "remote_node_bssid=");
		strcat(out_buf, blobmsg_get_string(tb_remote[USTEER_EVENT_NODE_STATUS_BSSID]));
	}

	if (tb_local[USTEER_EVENT_NODE_STATUS_FREQUENCY]) {
		snprintf(tmp_buf, 64, ",local_node_frequency=%d", blobmsg_get_u32(tb_local[USTEER_EVENT_NODE_STATUS_FREQUENCY]));
		strcat(out_buf, tmp_buf);
	}

	if (tb_remote[USTEER_EVENT_NODE_STATUS_FREQUENCY]) {
		snprintf(tmp_buf, 64, ",remote_node_frequency=%d", blobmsg_get_u32(tb_remote[USTEER_EVENT_NODE_STATUS_FREQUENCY]));
		strcat(out_buf, tmp_buf);
	}

	if (tb[USTEER_EVENT_STA]) {
		snprintf(tmp_buf, 64, " sta=\"%s\"", blobmsg_get_string(tb[USTEER_EVENT_STA]));
		strcat(out_buf, tmp_buf);
	}

	if (tb[USTEER_EVENT_REASON]) {
		snprintf(tmp_buf, 64, ",reason=\"%s\"", blobmsg_get_string(tb[USTEER_EVENT_REASON]));
		strcat(out_buf, tmp_buf);
	}

	if (tb[USTEER_EVENT_SELECT_REASON]) {
		for (i = 0; i < USTEER_EVENT_SELECT_REASON_LEN; i++) {
			if (!tb_select_reason[i])
				continue;
			snprintf(tmp_buf, 64, ",select_reason_%s=T", blobmsg_get_string(tb_select_reason[i]));
			strcat(out_buf, tmp_buf);
		}
	}

	if (tb[USTEER_EVENT_SIGNAL]) {
		snprintf(tmp_buf, 64, ",signal_local=%d", blobmsg_get_u32(tb[USTEER_EVENT_SIGNAL]));
		strcat(out_buf, tmp_buf);
	}

	if (tb_remote[USTEER_EVENT_NODE_STATUS_SIGNAL]) {
		snprintf(tmp_buf, 64, ",signal_remote=%d", blobmsg_get_u32(tb_remote[USTEER_EVENT_NODE_STATUS_SIGNAL]));
		strcat(out_buf, tmp_buf);
	}


	gettimeofday(&tv, NULL);
	millisecondsSinceEpoch = (unsigned long long)(tv.tv_sec) * 1000 +
				 (unsigned long long)(tv.tv_usec) / 1000;
	snprintf(tmp_buf, 64, " %llu", millisecondsSinceEpoch);
	strcat(out_buf, tmp_buf);

	return strdup(out_buf);
}

static void usteer_influxdb_submit() {
	static char token_buf[1024];
	snprintf(token_buf, 1024, "Token %s", config.token);
	static struct uclient_header headers[1] = {
		{ .name = "Authorization", .value = token_buf }
	};
	static char url_buf[1024];

	snprintf(url_buf, 1024, "%s/write?org=%s&bucket=%s&precision=ms", config.api_root, config.organization, config.bucket);
	usteer_influxdb_start_submission(url_buf, headers, 1);
}

static void usteer_influxdb_ubus_add_submission(char *subs) {
	char *tmpbuf;
	int bufsize;
	if (submission_queue == NULL) {
		submission_queue = strdup(subs);
		return;
	}

	bufsize = sizeof(char) * (strlen(submission_queue) + strlen(subs) + 2);	/* Newline char + NULL terminator */
	submission_queue = realloc(submission_queue, bufsize);

	tmpbuf = strdup(submission_queue);
	snprintf(submission_queue, bufsize, "%s\n%s", tmpbuf, subs);
	free(tmpbuf);
}

static int usteer_ubus_event_cb(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg) {
	struct blob_attr *tb[__USTEER_EVENT_MAX];
	struct blob_attr *tb_local[__USTEER_EVENT_NODE_STATUS_MAX];
	struct blob_attr *tb_remote[__USTEER_EVENT_NODE_STATUS_MAX];
	struct blob_attr *tb_select_reason[USTEER_EVENT_SELECT_REASON_LEN];

	memset(tb_remote, 0, sizeof(tb_remote));
	memset(tb_local, 0, sizeof(tb_local));

	blobmsg_parse(usteer_event_policy, __USTEER_EVENT_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (tb[USTEER_EVENT_NODE_LOCAL]) {
		blobmsg_parse(usteer_event_node_status_policy, __USTEER_EVENT_NODE_STATUS_MAX, tb_local,
			      blobmsg_data(tb[USTEER_EVENT_NODE_LOCAL]),
			      blobmsg_data_len(tb[USTEER_EVENT_NODE_LOCAL]));
	}

	if (tb[USTEER_EVENT_NODE_REMOTE]) {
		blobmsg_parse(usteer_event_node_status_policy, __USTEER_EVENT_NODE_STATUS_MAX, tb_remote,
			      blobmsg_data(tb[USTEER_EVENT_NODE_REMOTE]),
			      blobmsg_data_len(tb[USTEER_EVENT_NODE_REMOTE]));
	}

	if (tb[USTEER_EVENT_SELECT_REASON]) {
		blobmsg_parse_array(usteer_event_select_reason_policy, USTEER_EVENT_SELECT_REASON_LEN, tb_select_reason,
				    blobmsg_data(tb[USTEER_EVENT_SELECT_REASON]),
				    blobmsg_data_len(tb[USTEER_EVENT_SELECT_REASON]));
	}

	char *submission_str;
	submission_str = usteer_influxdb_get_submission(method, tb, tb_local, tb_remote, tb_select_reason);

	if (submission_str) {
		printf("%s\n", submission_str);
		usteer_influxdb_ubus_add_submission(submission_str);
		free(submission_str);
	}

	return 0;
}

static void
usteer_ubus_remove_cb(struct ubus_context *ctx, struct ubus_subscriber *s,
		      uint32_t id)
{
	return;
}

static void usteer_influxdb_register_usteer(struct ubus_context *ctx, const char *name, uint32_t id)
{
	static struct ubus_subscriber usteer_influxdb_ubus_subscriber = {
		.cb = usteer_ubus_event_cb,
		.remove_cb = usteer_ubus_remove_cb
	};

	if (strcmp(name, USTEER_OBJECT_NAME) != 0) {
		return;
	}

	if (ubus_register_subscriber(ctx, &usteer_influxdb_ubus_subscriber)) {
		printf("Could not register subscriber to ubus\n");
		return;
	}

	if (ubus_subscribe(ctx, &usteer_influxdb_ubus_subscriber, id)) {
		printf("Could not subscribe to ubus\n");
		return;
	}
}

static void usteer_influxdb_event_handler(struct ubus_context *ctx,
					  struct ubus_event_handler *ev,
					  const char *type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy[2] = {
		{ .name = "id", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "path", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[2];
	const char *path;

	blobmsg_parse(policy, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	path = blobmsg_data(tb[1]);
	usteer_influxdb_register_usteer(ctx, path, blobmsg_get_u32(tb[0]));
}

static void
usteer_list_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	usteer_influxdb_register_usteer(ctx, obj->path, obj->id);
}

void usteer_influxdb_register_events(struct ubus_context *ctx)
{
	static struct ubus_event_handler handler = {
	    .cb = usteer_influxdb_event_handler
	};

	usteer_influxdb_submit();

	ubus_register_event_handler(ctx, &handler, "ubus.object.add");

	ubus_lookup(ctx, "usteer", usteer_list_cb, NULL);
}