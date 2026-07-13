#include "packer.h"

#define WAIT_START_DEF 0

void unit_packer_init_no_func(Packer_t *packer)
{
	 packer->unpack_state = WAIT_START_DEF;
		    packer->unpack_crc = 0;
		    packer->unpack_offset  = 0;
		    packer->unpack_length = 0;
}




void unit_packer_init(Packer_t *packer, pack_data pack, unpack_data_byte unpack)
{

    packer->pack = pack;
    packer->unpack = unpack;
    unit_packer_init_no_func(packer);
}

void set_packer_process(Packer_t *packer, pack_data pack, unpack_data_byte unpack)
{
    packer->pack = pack;
    packer->unpack = unpack;
    unit_packer_init_no_func(packer);
}
