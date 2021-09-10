#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <unistd.h>
#include <uci.h>

#include "ubus.h"
#include "usteer-influxdb.h"

struct ui_settings config;

static int usteer_influxdb_config_load()
{
	struct uci_context *uci_ctx = uci_alloc_context();
	struct uci_package *uci_pkg;
	struct uci_section *uci_sec;
	const char *cptr;
	int ret = 0;

	if (!uci_ctx)
		return 1;

	ret = uci_load(uci_ctx, "usteer-influxdb", &uci_pkg);
	if (ret) {
		fprintf(stderr, "Could not access UCI package");
		ret = -ENOENT;
		goto out;
	}

	uci_sec = uci_lookup_section(uci_ctx, uci_pkg, "settings");

	cptr = uci_lookup_option_string(uci_ctx, uci_sec, "host");
	if (!cptr)
		goto out_err;
	config.host = strdup(cptr);

	cptr = uci_lookup_option_string(uci_ctx, uci_sec, "token");
	if (!cptr)
		goto out_err;
	config.token = strdup(cptr);

	cptr = uci_lookup_option_string(uci_ctx, uci_sec, "organization");
	if (!cptr)
		goto out_err;
	config.organization = strdup(cptr);

	cptr = uci_lookup_option_string(uci_ctx, uci_sec, "bucket");
	if (!cptr)
		goto out_err;
	config.bucket = strdup(cptr);

out:
	uci_free_context(uci_ctx);
	return ret;

out_err:
	return 1;
}

int main(int argc, char *argv[])
{
	struct ubus_context *ubus_ctx;

	if (usteer_influxdb_config_load())
		return 1;

	ubus_ctx = ubus_connect(NULL);
	uloop_init();
	ubus_add_uloop(ubus_ctx);

	usteer_influxdb_register_events(ubus_ctx);

	uloop_run();

	uloop_done();
	
	return 0;
}