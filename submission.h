#pragma once

struct uclient_data {
	/* data that can be passed in by caller and used in custom callbacks */
	void *custom;
	int err_code;
	int done;
};

struct uclient_header {
	char *name;
	char *value;
};

int post_url(const char *url, struct uclient_header *headers, int num_headers, char *post_data);

void usteer_influxdb_start_submission(const char *url, struct uclient_header *headers, int num_headers);
