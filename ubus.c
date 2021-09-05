#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "ubus.h"

#define USTEER_OBJECT_NAME	"usteer"

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
	[USTEER_EVENT_SIGNAL] = { "sta", BLOBMSG_TYPE_INT32 },
	[USTEER_EVENT_REASON] = { "reason", BLOBMSG_TYPE_STRING },
	[USTEER_EVENT_THRESHOLD] = { "threshold", BLOBMSG_TYPE_ARRAY },
	[USTEER_EVENT_SELECT_REASON] = { "select_reason", BLOBMSG_TYPE_ARRAY },
	[USTEER_EVENT_COUNT] = { "count", BLOBMSG_TYPE_INT32 },
};

static int usteer_ubus_event_cb(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg) {
	struct blob_attr *tb[__USTEER_EVENT_MAX];

	blobmsg_parse(usteer_event_policy, __USTEER_EVENT_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	printf("%s - %s\n", method, blobmsg_get_string(tb[USTEER_EVENT_REASON]));

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

	ubus_register_event_handler(ctx, &handler, "ubus.object.add");

	ubus_lookup(ctx, "usteer", usteer_list_cb, NULL);
}