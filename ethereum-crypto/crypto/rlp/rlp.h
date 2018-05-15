#ifndef _ETHEREUM_RLP_H_
#define _ETHEREUM_RLP_H_


#include <stdbool.h>
#include <stdint.h>
#include "utils.h"


#define PB_BYTES_ARRAY_T(n) struct { uint32_t size; uint8_t bytes[n]; }


typedef PB_BYTES_ARRAY_T(32) EthereumSignTx_nonce_t;
typedef PB_BYTES_ARRAY_T(32) EthereumSignTx_gas_price_t;
typedef PB_BYTES_ARRAY_T(32) EthereumSignTx_gas_limit_t;
typedef PB_BYTES_ARRAY_T(20) EthereumSignTx_to_t;
typedef PB_BYTES_ARRAY_T(32) EthereumSignTx_value_t;
typedef PB_BYTES_ARRAY_T(1024) EthereumSignTx_data_initial_chunk_t;

typedef struct _EthereumSignTx {
    EthereumSignTx_nonce_t nonce;
    EthereumSignTx_gas_price_t gas_price;
    EthereumSignTx_gas_limit_t gas_limit;
    EthereumSignTx_to_t to;
    EthereumSignTx_value_t value;
    EthereumSignTx_data_initial_chunk_t data_initial_chunk;
} EthereumSignTx;

typedef PB_BYTES_ARRAY_T(64) EthereumTxRequest_signature_r_t;
typedef PB_BYTES_ARRAY_T(64) EthereumTxRequest_signature_s_t;
typedef struct _EthereumTxRequest {
    uint32_t data_length;
    uint32_t signature_v;
    EthereumTxRequest_signature_r_t signature_r;
    EthereumTxRequest_signature_s_t signature_s;
} EthereumSig;

int rlp_encode_list(EthereumSignTx *new_msg, EthereumSig *new_tx, uint64_t *rawTx);
void rlp_encode_element(uint8_t *bytes, uint32_t size, uint8_t *new_bytes, uint32_t *new_size);
void rlp_encode_int(uint32_t singleInt, uint8_t *new_bytes);
int rlp_encode_tx_list(EthereumSignTx *new_msg, uint64_t *rawTx);


#endif
