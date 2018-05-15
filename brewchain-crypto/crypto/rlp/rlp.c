#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "rlp.h"


#define SIZE_THRESHOLD     56
#define OFFSET_SHORT_LIST  0xc0
#define OFFSET_LONG_LIST   0xf7
#define OFFSET_LONG_ITEM   0xb7
#define OFFSET_SHORT_ITEM  0x80


static int rlp_copy(uint8_t *source, uint8_t *destination, uint8_t size, int copyPos)
{
    int ret_val = copyPos;

    if (size > 0) {
        memcpy(source, destination, size);
        ret_val = ret_val + size;
    }

    return ret_val;
}


int rlp_encode_tx_list(EthereumSignTx *new_msg, uint64_t *rawTx)
{
    int i, copyPos;
    uint8_t *data;
    uint8_t *lenBytes;
    uint32_t totalLength = 0;

    totalLength += new_msg->nonce.size;
    totalLength += new_msg->gas_price.size;
    totalLength += new_msg->gas_limit.size;
    totalLength += new_msg->to.size;
    totalLength += new_msg->value.size;
    totalLength += new_msg->data_initial_chunk.size;

    if (totalLength < SIZE_THRESHOLD) {
        data = malloc(1 + totalLength);
        data[0] = (int8_t)(OFFSET_SHORT_LIST + totalLength);
        copyPos = 1;
    } else {
        int tmpLength = totalLength;
        uint8_t byteNum = 0;
        while (tmpLength != 0) {
            ++byteNum;
            tmpLength = tmpLength >> 8;
        }
        tmpLength = totalLength;
        lenBytes = malloc(byteNum);
        for (i = 0; i < byteNum; ++i) {
            lenBytes[byteNum - 1 - i] = (uint8_t)((tmpLength >> (8 * i)) & 0xFF);
        }
        data = malloc(1 + byteNum + totalLength);
        data[0] = (uint8_t)(OFFSET_LONG_LIST + byteNum);
        memcpy(data + 1, lenBytes, byteNum);
        copyPos = byteNum + 1;
        free(lenBytes);
    }

    copyPos = rlp_copy(data + copyPos,
            new_msg->nonce.bytes,
            new_msg->nonce.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->gas_price.bytes,
            new_msg->gas_price.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->gas_limit.bytes,
            new_msg->gas_limit.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->to.bytes,
            new_msg->to.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->value.bytes,
            new_msg->value.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->data_initial_chunk.bytes,
            new_msg->data_initial_chunk.size, copyPos);

    memcpy(rawTx, data, copyPos);
    free(data);

    return copyPos;
}


int rlp_encode_list(EthereumSignTx *new_msg, EthereumSig *new_tx, uint64_t *rawTx)
{
    int i, copyPos;
    uint8_t *data;
    uint8_t *lenBytes;
    uint32_t totalLength = 0;

    totalLength += new_msg->nonce.size;
    totalLength += new_msg->gas_price.size;
    totalLength += new_msg->gas_limit.size;
    totalLength += new_msg->to.size;
    totalLength += new_msg->value.size;
    totalLength += new_msg->data_initial_chunk.size;

    totalLength += 1; /* tx->signature_v.size */
    totalLength += new_tx->signature_r.size;
    totalLength += new_tx->signature_s.size;

    if (totalLength < SIZE_THRESHOLD) {
        data = malloc(1 + totalLength);
        data[0] = (int8_t)(OFFSET_SHORT_LIST + totalLength);
        copyPos = 1;
    } else {
        int tmpLength = totalLength;
        uint8_t byteNum = 0;
        while (tmpLength != 0) {
            ++byteNum;
            tmpLength = tmpLength >> 8;
        }
        tmpLength = totalLength;
        lenBytes = malloc(byteNum);
        for (i = 0; i < byteNum; ++i) {
            lenBytes[byteNum - 1 - i] = (uint8_t)((tmpLength >> (8 * i)) & 0xFF);
        }
        data = malloc(1 + byteNum + totalLength);
        data[0] = (uint8_t)(OFFSET_LONG_LIST + byteNum);
        memcpy(data + 1, lenBytes, byteNum);
        copyPos = byteNum + 1;
        free(lenBytes);
    }

    copyPos = rlp_copy(data + copyPos,
            new_msg->nonce.bytes,
            new_msg->nonce.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->gas_price.bytes,
            new_msg->gas_price.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->gas_limit.bytes,
            new_msg->gas_limit.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->to.bytes,
            new_msg->to.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->value.bytes,
            new_msg->value.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_msg->data_initial_chunk.bytes,
            new_msg->data_initial_chunk.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            (uint8_t *)&new_tx->signature_v, 1, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_tx->signature_r.bytes,
            new_tx->signature_r.size, copyPos);

    copyPos = rlp_copy(data + copyPos,
            new_tx->signature_s.bytes,
            new_tx->signature_s.size, copyPos);

    memcpy(rawTx, data, copyPos);
    free(data);

    return copyPos;
}


void rlp_encode_element(uint8_t *bytes, uint32_t size,
        uint8_t *new_bytes, uint32_t *new_size)
{
    int i;
    uint8_t *data;

    if (size == 0) {
        *new_size = 1;
        new_bytes[0] = (uint8_t)OFFSET_SHORT_ITEM;
    } else if (size == 1 && bytes[0] == 0x00) {
        *new_size = 1;
        new_bytes[0] = bytes[0];
    } else if (size == 1 && ((bytes[0] & 0xFF) == 0)) {
        *new_size = 1;
        new_bytes[0] = bytes[0];
    } else if (size == 1 && (bytes[0] & 0xFF) < 0x80) {
        *new_size = 1;
        new_bytes[0] = bytes[0];
    } else if (size < SIZE_THRESHOLD) {
        uint8_t length = (uint8_t)(OFFSET_SHORT_ITEM + size);
        new_bytes[0] = length;
        memcpy(new_bytes + 1, bytes, size);
        *new_size = size + 1;
    } else {
        int tmpLength = size;
        uint8_t lengthOfLength = (uint8_t)0;
        while (tmpLength != 0) {
            ++lengthOfLength;
            tmpLength = tmpLength >> 8;
        }
        data = malloc(1 + lengthOfLength + size);
        data[0] = (uint8_t)(OFFSET_LONG_ITEM + lengthOfLength);
        tmpLength = size;
        for (i = lengthOfLength; i > 0; --i) {
            data[i] = (uint8_t)(tmpLength & 0xFF);
            tmpLength = tmpLength >> 8;
        }
        memcpy(data + 1 + lengthOfLength, bytes, size);
        memcpy(new_bytes, data, ((1 + lengthOfLength + size)));
        *new_size = (1 + lengthOfLength + size);
        free(data);
    }
}


static void rlp_encode_byte(uint8_t singleByte, uint8_t *new_bytes)
{
    if ((singleByte & 0xFF) == 0) {
        new_bytes[0] = (uint8_t)OFFSET_SHORT_ITEM;
    } else if ((singleByte & 0xFF) <= 0x7F) {
        new_bytes[0] = (uint8_t)singleByte;
    } else {
        new_bytes[0] = (uint8_t)(OFFSET_SHORT_ITEM + 1);
        new_bytes[1] = singleByte;
    }
}


static void rlp_encode_short(uint16_t singleShort, uint8_t *new_bytes)
{
    if ((singleShort & 0xFF) == singleShort) {
        rlp_encode_byte((uint8_t)singleShort, new_bytes);
    } else {
        new_bytes[0] = (uint8_t)(OFFSET_SHORT_ITEM + 2);
        new_bytes[1] = (singleShort >> 8 & 0xFF);
        new_bytes[2] = (singleShort >> 0 & 0xFF);
    }
}


void rlp_encode_int(uint32_t singleInt, uint8_t *new_bytes)
{
    if ((singleInt & 0xFF) == singleInt) {
        rlp_encode_byte((uint8_t)singleInt, new_bytes);
    } else if ((singleInt & 0xFFFF) == singleInt) {
        rlp_encode_short((uint16_t)singleInt, new_bytes);
    } else if ((singleInt & 0xFFFFFF) == singleInt) {
        new_bytes[0] = (uint8_t)(OFFSET_SHORT_ITEM + 3);
        new_bytes[1] = (uint8_t)(singleInt >> 16);
        new_bytes[2] = (uint8_t)(singleInt >> 8);
        new_bytes[3] = (uint8_t)(singleInt);
    } else {
        new_bytes[0] = (uint8_t)(OFFSET_SHORT_ITEM + 4);
        new_bytes[1] = (uint8_t)(singleInt >> 24);
        new_bytes[2] = (uint8_t)(singleInt >> 16);
        new_bytes[3] = (uint8_t)(singleInt >> 8);
        new_bytes[4] = (uint8_t)(singleInt);
    }
}
