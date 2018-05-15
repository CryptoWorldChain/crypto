#include <stdint.h>
#include <stdlib.h>
#include <jni.h>
#include "sm4.h"


JNIEXPORT jlong JNICALL Java_crypto_SmCrypto_createContext(
        JNIEnv *env, jobject this)
{
    return (uintptr_t)calloc(1, sizeof(sm4_context));
}


JNIEXPORT void JNICALL Java_crypto_SmCrypto_destroyContext(
        JNIEnv *env, jobject this, jlong context_)
{
    free((void *)(uintptr_t)context_);
}


JNIEXPORT jboolean JNICALL Java_crypto_SmCrypto_setKeyEnc(
        JNIEnv *env, jobject this, jlong context_, jbyteArray key_)
{
    sm4_context *context;
    unsigned char *key;

    if ((*env)->GetArrayLength(env, key_) != 16) {
        return JNI_FALSE;
    }

    key = (unsigned char *)(*env)->GetByteArrayElements(env, key_, JNI_FALSE);
    context = (sm4_context *)(uintptr_t)context_;
    sm4_setkey_enc(context, key);

    return JNI_TRUE;
}


JNIEXPORT jboolean JNICALL Java_crypto_SmCrypto_setKeyDec(
        JNIEnv *env, jobject this, jlong context_, jbyteArray key_)
{
    sm4_context *context;
    unsigned char *key;

    if ((*env)->GetArrayLength(env, key_) != 16) {
        return JNI_FALSE;
    }

    key = (unsigned char *)(*env)->GetByteArrayElements(env, key_, JNI_FALSE);
    context = (sm4_context *)(uintptr_t)context_;
    sm4_setkey_dec(context, key);

    return JNI_TRUE;
}


JNIEXPORT jbyteArray JNICALL Java_crypto_SmCrypto_cryptEcb(
        JNIEnv *env, jobject this, jlong context_,
        jint mode_, jbyteArray input_)
{
    int length;
    unsigned char *input;
    unsigned char *output;
    jbyteArray result;
    sm4_context *context;

    length = (int)(*env)->GetArrayLength(env, input_);
    output = (unsigned char *)calloc(1, (size_t)length);
    if (output == NULL) {
        return NULL;
    }

    input = (unsigned char *)(*env)->GetByteArrayElements(env, input_, JNI_FALSE);
    context = (sm4_context *)(uintptr_t)context_;
    sm4_crypt_ecb(context, (int)mode_, length, input, output);
    result = (*env)->NewByteArray(env, (jsize)length);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)length, (jbyte *)output);

    free(output);

    return result;
}
