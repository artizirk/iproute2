/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "ip_common.h"

static void print_usage(FILE *f)
{
	fprintf(f,
		"Usage: ... wireguard\n"
		"		[listen-port  <port>]\n"
		"		[fwmark <fwmark>]\n"
		"		[private-key <file-path>]\n"
		"		[peer <base64-public-key>\n"
		"			[remove]\n"
		"			[preshared-key  <file-path>]\n"
		"			[endpoint <ip>:<port>]\n"
		"			[persistent-keepalive <interval seconds>]\n"
		"			[allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...]\n"
		"		]...\n"
		);
}

static void usage(void)
{
	print_usage(stderr);
}

static void wireguard_print_help(struct link_util *lu,
			    int argc, char **argv, FILE *f)
{
	print_usage(f);
}

static int wireguard_parse_opt(struct link_util *lu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	while (argc > 0) {
		if (matches(*argv, "listen-port") == 0) {
			uint16_t listen_port = 0;

			NEXT_ARG();
			if (get_u16(&listen_port, *argv, 0))
				invarg("invalid \"listen-port\" value\n", *argv);

			printf("listen_port %d\n", listen_port);
		} else if (matches(*argv, "fwmark") == 0) {
			uint32_t fwmark = 0;

			NEXT_ARG();
			if (get_u32(&fwmark, *argv, 0))
				invarg("invalid \"fwmark\" value\n",
					   *argv);
			printf("fwmark %d\n", fwmark);
		} else {
			fprintf(stderr, "wireguard: unknown option \"%s\"\n", *argv);
			usage();
			return -1;
		}
		argc--, argv++;
	}

	return 0;
}

struct link_util wireguard_link_util = {
	.id		= "wireguard",
	.print_help	= wireguard_print_help,
	.parse_opt	= wireguard_parse_opt
};
