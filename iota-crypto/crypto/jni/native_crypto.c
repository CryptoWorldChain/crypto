#include <stdint.h>
#include <stdlib.h>
#include <jni.h>
#include "sign.h"
#include "validate.h"
#include "generate.h"


JNIEXPORT jstring JNICALL Java_crypto_IotaCrypto_generateSeed(
        JNIEnv *env, jobject this)
{
    const char *seed;
    jstring jstrSeed;

    seed = iota_generateSeed();
    jstrSeed = (*env)->NewStringUTF(env, seed);
    free((void *)seed);

    return jstrSeed;
}


JNIEXPORT jstring JNICALL Java_crypto_IotaCrypto_generateKey(
        JNIEnv *env, jobject this, jstring seed_,
        jint keyIndex_, jint securityLevel_)
{
    const char *seed;
    const char *key;
    jstring jstrKey;

    seed = (*env)->GetStringUTFChars(env, seed_, JNI_FALSE);
    key = iota_generateKey(seed, (int)keyIndex_, (int)securityLevel_);
    jstrKey = (*env)->NewStringUTF(env, key);
    (*env)->ReleaseStringUTFChars(env, seed_, seed);
    free((void *)key);

    return jstrKey;
}


JNIEXPORT jstring JNICALL Java_crypto_IotaCrypto_generateAddress(
        JNIEnv *env, jobject this, jstring seed_,
        jint keyIndex_, jint securityLevel_)
{
    const char *seed;
    const char *address;
    jstring jstrAddress;

    seed = (*env)->GetStringUTFChars(env, seed_, JNI_FALSE);
    address = iota_generateAddress(seed, (int)keyIndex_, (int)securityLevel_);
    jstrAddress = (*env)->NewStringUTF(env, address);
    (*env)->ReleaseStringUTFChars(env, seed_, seed);
    free((void *)address);

    return jstrAddress;
}


JNIEXPORT jstring JNICALL Java_crypto_IotaCrypto_signTransaction(
        JNIEnv *env, jobject this, jbyteArray normalizedFragment_,
        jbyteArray keyTrytes_)
{
    const int8_t *normalizedFragment;
    const char *keyTrytes;
    const char *signature;
    jstring jstrSignature;

    normalizedFragment = (const int8_t *)(*env)->GetByteArrayElements(env, normalizedFragment_, JNI_FALSE);
    keyTrytes = (const char *)(*env)->GetByteArrayElements(env, keyTrytes_, JNI_FALSE);
    signature = iota_sign(normalizedFragment, keyTrytes);
    jstrSignature = (*env)->NewStringUTF(env, signature);
    free((void *)signature);

    return jstrSignature;
}


JNIEXPORT jboolean JNICALL Java_crypto_IotaCrypto_validateSignature(
        JNIEnv *env, jobject this, jstring address_,
        jobjectArray signFrags_, jstring bundleHash_)
{
    int index, signFragsLen;
    char **signFrags;
    char isValidSignature;
    const char *address;
    const char *bundleHash;

    signFragsLen = (int)(*env)->GetArrayLength(env, signFrags_);
    signFrags = (char **)calloc(signFragsLen, sizeof(char *));

    for (index = 0; index < signFragsLen; index++) {
        signFrags[index] = (char *)(*env)->GetObjectArrayElement(env, signFrags_, index);
    }

    address = (*env)->GetStringUTFChars(env, address_, JNI_FALSE);
    bundleHash = (*env)->GetStringUTFChars(env, bundleHash_, JNI_FALSE);
    isValidSignature = iota_validateSignature(address, (const char **)signFrags, signFragsLen, bundleHash);
    (*env)->ReleaseStringUTFChars(env, address_, address);
    (*env)->ReleaseStringUTFChars(env, bundleHash_, bundleHash);
    free((void *)signFrags);

    return (isValidSignature ? JNI_TRUE : JNI_FALSE);
}
