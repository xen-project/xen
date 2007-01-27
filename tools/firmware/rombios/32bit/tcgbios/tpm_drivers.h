#ifndef TPM_DRIVER_H
/* low level driver implementation */
struct tpm_driver {
	uint32_t baseaddr;
	uint32_t (*activate)(uint32_t baseaddr);
	uint32_t (*ready)(uint32_t baseaddr);
	uint32_t (*senddata)(uint32_t baseaddr, unsigned char *data, uint32_t len);
	uint32_t (*readresp)(uint32_t baseaddr, unsigned char *buffer, uint32_t len);
	uint32_t (*waitdatavalid)(uint32_t baseaddr);
	uint32_t (*waitrespready)(uint32_t baseaddr, uint32_t timeout);
	uint32_t (*probe)(uint32_t baseaddr);
};

#define TPM_NUM_DRIVERS      1

#define TPM_INVALID_DRIVER  -1

#endif
