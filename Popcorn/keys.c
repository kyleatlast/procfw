#include "keys.h"

#include <pspiofilemgr.h>
#include <pspinit.h>
#include <pspcrypt.h>
#include <string.h>

#define KIRK7_HEADER_SIZE 0x14
#define VERSION_KEY_SIZE 0x10

typedef struct {
	int type;
	u8 key[16];
	u8 pad[16];
	int pad_size;
} MAC_KEY;

int sceDrmBBMacInit(MAC_KEY *mkey, int type);
int sceDrmBBMacUpdate(MAC_KEY *mkey, u8 *buf, int size);
int sceDrmBBMacFinal(MAC_KEY *mkey, u8 *buf, u8 *vkey);

static int kirk7(u8 *buf, int size, int type) {
	u32 *header = (u32 *)buf;

	header[0] = 5;
	header[1] = 0;
	header[2] = 0;
	header[3] = type;
	header[4] = size;

	return sceUtilsBufferCopyWithRange(buf, size + KIRK7_HEADER_SIZE, buf, size, 7);
}

u32 extract_keys(unsigned char *out_keys)
{
	SceUID fd = -1;
	const char *filename;
	int result, ret;
	u32 psar_offset, pgd_offset;
	u8 p[40 + 64], *header;

	header = (u8*)((((u32)p) & ~(64-1)) + 64);
	filename = sceKernelInitFileName();
	result = 0;

	if(filename == NULL) {
		result = 0;
		goto exit;
	}

	fd = sceIoOpen(filename, PSP_O_RDONLY, 0777);

	if(fd < 0) {
		result = 0;
		goto exit;
	}

	ret = sceIoRead(fd, header, 40);

	if(ret != 40) {
		result = 0;
		goto exit;
	}

	psar_offset = *(u32*)(header+0x24);
	sceIoLseek32(fd, psar_offset, PSP_SEEK_SET);
	ret = sceIoRead(fd, header, 40);

	if(ret != 40) {
		result = 0;
		goto exit;
	}

	pgd_offset = psar_offset;

	if(0 == memcmp(header, "PSTITLE", sizeof("PSTITLE")-1)) {
		pgd_offset += 0x200;
	} else {
		pgd_offset += 0x400;
	}

	sceIoLseek32(fd, pgd_offset, PSP_SEEK_SET);

    unsigned char pgd_buf[0x80];

	sceIoRead(fd, pgd_buf, 0x80);

    // Set mac type
    int mac_type = 0;

    if (((u32 *)pgd_buf)[2] == 1) {
        mac_type = 1;

        if (((u32 *)pgd_buf)[1] > 1)
            mac_type = 3;
    } else {
        mac_type = 2;
    }

    // Generate the key from MAC 0x70 
    MAC_KEY mac_key;
    sceDrmBBMacInit(&mac_key, mac_type);
    sceDrmBBMacUpdate(&mac_key, pgd_buf, 0x70);

    u8 xor_keys[VERSION_KEY_SIZE];
    sceDrmBBMacFinal(&mac_key, xor_keys, NULL);

    u8 kirk_buf[VERSION_KEY_SIZE + KIRK7_HEADER_SIZE];

    if (mac_key.type == 3) {
        memcpy(kirk_buf + KIRK7_HEADER_SIZE, pgd_buf + 0x70, VERSION_KEY_SIZE);
        kirk7(kirk_buf, VERSION_KEY_SIZE, 0x63);
    } else {
        memcpy(kirk_buf, pgd_buf + 0x70, VERSION_KEY_SIZE);
    }

    memcpy(kirk_buf + KIRK7_HEADER_SIZE, kirk_buf, VERSION_KEY_SIZE);
    kirk7(kirk_buf, VERSION_KEY_SIZE, (mac_key.type == 2) ? 0x3A : 0x38);

    // Get version key
    int i;
    for (i = 0; i < VERSION_KEY_SIZE; i++) {
        out_keys[i] = xor_keys[i] ^ kirk_buf[i];
    }
    result = 1;

exit:
	if(fd >= 0) {
		sceIoClose(fd);
	}

	return result;
}

