/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <string.h>

#ifdef USE_MINGW
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "ext4_utils.h"
#include "sha1.h"
#include "uuid.h"

/* Definition from RFC-4122 */
struct uuid {
	u32 time_low;
	u16 time_mid;
	u16 time_hi_and_version;
	u8 clk_seq_hi_res;
	u8 clk_seq_low;
	u16 node0_1;
	u32 node2_5;
};

static void sha1_hash(const char *namespace, const char *name,
	unsigned char sha1[SHA1_DIGEST_LENGTH])
{
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, (const u8*)namespace, strlen(namespace));
	SHA1Update(&ctx, (const u8*)name, strlen(name));
	SHA1Final(sha1, &ctx);
}

void generate_uuid(const char *namespace, const char *name, u8 result[16])
{
	unsigned char sha1[SHA1_DIGEST_LENGTH];
	struct uuid *uuid = (struct uuid *)result;

	sha1_hash(namespace, name, (unsigned char*)sha1);
	memcpy(uuid, sha1, sizeof(struct uuid));

	uuid->time_low = ntohl(uuid->time_low);
	uuid->time_mid = ntohs(uuid->time_mid);
	uuid->time_hi_and_version = ntohs(uuid->time_hi_and_version);
	uuid->time_hi_and_version &= 0x0FFF;
	uuid->time_hi_and_version |= (5 << 12);
	uuid->clk_seq_hi_res &= ~(1 << 6);
	uuid->clk_seq_hi_res |= 1 << 7;
}

static void uuid_pack(const struct uuid *uu, uuid_t ptr)
{
	uint32_t	tmp;
	unsigned char	*out = ptr;

	tmp = uu->time_low;
	out[3] = (unsigned char) tmp;
	tmp >>= 8;
	out[2] = (unsigned char) tmp;
	tmp >>= 8;
	out[1] = (unsigned char) tmp;
	tmp >>= 8;
	out[0] = (unsigned char) tmp;

	tmp = uu->time_mid;
	out[5] = (unsigned char) tmp;
	tmp >>= 8;
	out[4] = (unsigned char) tmp;

	tmp = uu->time_hi_and_version;
	out[7] = (unsigned char) tmp;
	tmp >>= 8;
	out[6] = (unsigned char) tmp;

	out[9] = (unsigned char) uu->clk_seq_low;
	out[8] = (unsigned char) uu->clk_seq_hi_res;

	memcpy(out+10, &uu->node0_1, 6);
}

int uuid_parse(const char *in, uuid_t uu)
{
	struct uuid	uuid;
	int 		i;
	const char	*cp;
	char		buf[3];
	u16		clock_seq;
	u8	 	*node;

	if (strlen(in) != 36)
		return -1;
	for (i=0, cp = in; i <= 36; i++,cp++) {
		if ((i == 8) || (i == 13) || (i == 18) ||
		    (i == 23)) {
			if (*cp == '-')
				continue;
			else
				return -1;
		}
		if (i== 36)
			if (*cp == 0)
				continue;
		if (!isxdigit(*cp))
			return -1;
	}
	uuid.time_low = strtoul(in, NULL, 16);
	uuid.time_mid = strtoul(in+9, NULL, 16);
	uuid.time_hi_and_version = strtoul(in+14, NULL, 16);
	clock_seq = strtoul(in+19, NULL, 16);
	uuid.clk_seq_low = (u8) clock_seq & 0xff;
	uuid.clk_seq_hi_res = (u8) (clock_seq >> 8) & 0xff;
	cp = in+24;
	buf[2] = 0;
	node = (u8 *)&uuid.node0_1;
	for (i=0; i < 6; i++) {
		buf[0] = *cp++;
		buf[1] = *cp++;
		node[i] = strtoul(buf, NULL, 16);
	}

	uuid_pack(&uuid, uu);
	return 0;
}
