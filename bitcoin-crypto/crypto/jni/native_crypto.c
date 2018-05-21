#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include "tx.h"
#include "cstr.h"
#include "script.h"
#include "utils.h"
#include "tool.h"
#include "bip32.h"
#include "ecc.h"
#include "ecc_key.h"


JNIEXPORT void JNICALL Java_crypto_BitcoinCrypto_initEcc(
        JNIEnv *env, jobject this)
{
    btc_ecc_start();
}


JNIEXPORT void JNICALL Java_crypto_BitcoinCrypto_destroyEcc(
        JNIEnv *env, jobject this)
{
    btc_ecc_stop();
}


JNIEXPORT jobjectArray JNICALL Java_crypto_BitcoinCrypto_createAccount(
        JNIEnv *env, jobject this)
{
    char p2pkh_addr[100];
    char privkey_hex[65];
    char pubkey_hex[66];
    size_t size = 66;
    btc_key btckey;
    btc_pubkey pubkey;
    jstring strPrikey;
    jstring strPubkey;
    jstring strAddress;
    jclass  strClass;
    jobjectArray objArray;

    //generate private key
    btc_privkey_init(&btckey);
    btc_privkey_gen(&btckey);

    if (btc_privkey_is_valid(&btckey)) {
        return NULL;
    }

    utils_bin_to_hex(btckey.privkey, BTC_ECKEY_PKEY_LENGTH, privkey_hex);

    //generate public key
    btc_pubkey_init(&pubkey);
    btc_pubkey_from_key(&btckey, &pubkey);

    if (!btc_pubkey_is_valid(&pubkey)) {
        return NULL;
    }

    btc_pubkey_get_hex(&pubkey, pubkey_hex, &size);
    btc_pubkey_getaddr_p2pkh(&pubkey, &btc_chainparams_main, p2pkh_addr);

    strPrikey = (*env)->NewStringUTF(env, (char *)privkey_hex);
    strPubkey = (*env)->NewStringUTF(env, (char *)pubkey_hex);
    strAddress = (*env)->NewStringUTF(env, (char *)p2pkh_addr);
    strClass = (*env)->FindClass(env, "Ljava/lang/String;");
    objArray = (*env)->NewObjectArray(env, 3, strClass, NULL);
    (*env)->SetObjectArrayElement(env, objArray, 0, strPrikey);
    (*env)->SetObjectArrayElement(env, objArray, 1, strPubkey);
    (*env)->SetObjectArrayElement(env, objArray, 2, strAddress);

    return objArray;
}


JNIEXPORT jobjectArray JNICALL Java_crypto_BitcoinCrypto_recoverAccount(
        JNIEnv *env, jobject this, jlong context_, jstring prikey_)
{
    const char *prikey;
    char p2pkh_addr[100];
    char pubkey_hex[100];
    size_t pubkey_len = 100;
    size_t outlen = 0;
    btc_pubkey pubkey;
    jstring strPubkey;
    jstring strAddress;
    jclass  strClass;
    jobjectArray objArray;

    //generate public key
    prikey = (*env)->GetStringUTFChars(env, prikey_, JNI_FALSE);
    pubkey_from_privatekey(&btc_chainparams_main, prikey, pubkey_hex, &pubkey_len);
    (*env)->ReleaseStringUTFChars(env, prikey_, prikey);

    btc_pubkey_init(&pubkey);
    pubkey.compressed = 1;
    utils_hex_to_bin(pubkey_hex, pubkey.pubkey, strlen(pubkey_hex), (int*)&outlen);

    if (outlen != BTC_ECKEY_COMPRESSED_LENGTH
            || !btc_pubkey_is_valid(&pubkey)) {
        return NULL;
    }

    btc_pubkey_getaddr_p2pkh(&pubkey, &btc_chainparams_main, p2pkh_addr);

    strPubkey = (*env)->NewStringUTF(env, (char *)pubkey_hex);
    strAddress = (*env)->NewStringUTF(env, (char *)p2pkh_addr);
    strClass = (*env)->FindClass(env, "Ljava/lang/String;");
    objArray = (*env)->NewObjectArray(env, 3, strClass, NULL);
    (*env)->SetObjectArrayElement(env, objArray, 0, strPubkey);
    (*env)->SetObjectArrayElement(env, objArray, 1, strAddress);

    return objArray;
}


JNIEXPORT jstring JNICALL Java_crypto_BitcoinCrypto_signTransaction(
        JNIEnv *env, jobject this, jstring prikey_, jstring txhex_,
        jstring scripthex_, jint inputindex_, jint sighashtype_, jlong amount_)
{
    btc_key key;
    btc_tx *tx;
    cstring *script;
    uint256 sighash;
    char *hex;
    long int amount;
    int inputindex;
    int sighashtype;
    int outlen = 0;
    int sigderlen = 74+1; //&hashtype
    uint8_t *txbin;
    uint8_t sigcompact[64] = { 0 };
    uint8_t sigder_plus_hashtype[75] = { 0 };
    uint8_t script_data[4096];
    char sigcompacthex[64 * 2 + 1] = { 0 };
    char sigderhex[74 * 2 + 2 + 1]; //74 der, 2 hashtype, 1 nullbyte
    char signed_tx_hex[4096];
    const char *prikey;
    const char *txhex;
    const char *scripthex;
    size_t txhex_len;
    enum btc_tx_sign_result res;
    cstring *signed_tx;

    prikey = (*env)->GetStringUTFChars(env, prikey_, JNI_FALSE);
    txhex = (*env)->GetStringUTFChars(env, txhex_, JNI_FALSE);
    scripthex = (*env)->GetStringUTFChars(env, scripthex_, JNI_FALSE);

    inputindex = (int)inputindex_;
    sighashtype = (int)sighashtype_;
    amount = (long int)amount_;

    txhex_len = strlen(txhex);
    if (txhex_len > 102400) {
        //don't accept transaction larger than 100KB
        return NULL;
    }

    //deserialize transaction
    tx = btc_tx_new();
    txbin = btc_malloc(txhex_len / 2 + 1);
    utils_hex_to_bin(txhex, txbin, (int)txhex_len, &outlen);

    if (!btc_tx_deserialize(txbin, outlen, tx, NULL, true)) {
        free(txbin);
        btc_tx_free(tx);
        return NULL;
    }

    free(txbin);

    if ((size_t)inputindex >= tx->vin->len) {
        btc_tx_free(tx);
        return NULL;
    }

    utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
    script = cstr_new_buf(script_data, outlen);
    memset(sighash, 0, sizeof(sighash));
    btc_tx_sighash(tx, script, inputindex, sighashtype, 0, SIGVERSION_BASE, sighash);
    hex = utils_uint8_to_hex(sighash, 32);
    utils_reverse_hex(hex, 64);

    btc_privkey_init(&key);
    btc_privkey_decode_wif(prikey, &btc_chainparams_main, &key);

    res = btc_tx_sign_input(tx, script, amount, &key,
            inputindex, sighashtype, sigcompact,
            sigder_plus_hashtype, &sigderlen);

    cstr_free(script, true);

    if (res != BTC_SIGN_OK) {
        btc_tx_free(tx);
        (*env)->ReleaseStringUTFChars(env, prikey_, prikey);
        (*env)->ReleaseStringUTFChars(env, txhex_, txhex);
        (*env)->ReleaseStringUTFChars(env, scripthex_, scripthex);
        return NULL;
    }

    utils_bin_to_hex((unsigned char *)sigcompact, 64, sigcompacthex);
    memset(sigderhex, 0, sizeof(sigderhex));
    utils_bin_to_hex((unsigned char *)sigder_plus_hashtype, sigderlen, sigderhex);

    signed_tx = cstr_new_sz(1024);
    btc_tx_serialize(signed_tx, tx, true);
    utils_bin_to_hex((unsigned char *)signed_tx->str, signed_tx->len, signed_tx_hex);

    cstr_free(signed_tx, true);
    btc_tx_free(tx);

    (*env)->ReleaseStringUTFChars(env, prikey_, prikey);
    (*env)->ReleaseStringUTFChars(env, txhex_, txhex);
    (*env)->ReleaseStringUTFChars(env, scripthex_, scripthex);

    return (*env)->NewStringUTF(env, signed_tx_hex);
}


JNIEXPORT jint JNICALL Java_crypto_BitcoinCrypto_verifySignature(
        JNIEnv *env, jobject this, jbyteArray pubkey_,
        jbyteArray txhash_, jbyteArray sigdata_)
{
    btc_pubkey btcpubkey;
    size_t siglen, keylen;
    unsigned char *pubkey;
    unsigned char *txhash;
    unsigned char *sigdata;

    txhash = (unsigned char *)(*env)->GetByteArrayElements(env, txhash_, JNI_FALSE);

    sigdata = (unsigned char *)(*env)->GetByteArrayElements(env, sigdata_, JNI_FALSE);
    siglen = (size_t)(*env)->GetArrayLength(env, sigdata_);

    pubkey = (unsigned char *)(*env)->GetByteArrayElements(env, pubkey_, JNI_FALSE);
    keylen = (size_t)(*env)->GetArrayLength(env, pubkey_);

    btc_pubkey_init(&btcpubkey);
    btcpubkey.compressed = 1;
    memcpy(btcpubkey.pubkey, pubkey, keylen);

    return btc_pubkey_verify_sig(&btcpubkey, txhash, sigdata, siglen);
}
