#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "ubus.h"


int main(int argc, char *argv[])
{
	struct ubus_context *ubus_ctx;

	ubus_ctx = ubus_connect(NULL);
	uloop_init();
	ubus_add_uloop(ubus_ctx);

	usteer_influxdb_register_events(ubus_ctx);

	uloop_run();

	uloop_done();
	
	return 0;
}