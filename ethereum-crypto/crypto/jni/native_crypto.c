#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include "crypto.h"


JNIEXPORT jlong JNICALL Java_org_brewchain_core_crypto_jni_Crypto_createContext(
        JNIEnv *env, jobject this)
{
    return (uintptr_t)create_context();
}


JNIEXPORT void JNICALL Java_org_brewchain_core_crypto_jni_Crypto_destroyContext(
        JNIEnv *env, jobject this, jlong context_)
{
    destroy_context((void *)(uintptr_t)context_);
}


JNIEXPORT jobjectArray JNICALL Java_org_brewchain_core_crypto_jni_Crypto_createAccount(
        JNIEnv *env, jobject this, jlong context_)
{
    const void *context;
    uint8_t prikey[65];
    uint8_t pubkey[131];
    uint8_t address[41];
    jstring strPrikey;
    jstring strPubkey;
    jstring strAddress;
    jclass  strClass;
    jobjectArray objArray;

    context = (const void *)(uintptr_t)context_;
    create_account(context, prikey, 65, pubkey, 131, address, 41);
    strPrikey = (*env)->NewStringUTF(env, (char *)prikey);
    strPubkey = (*env)->NewStringUTF(env, (char *)pubkey);
    strAddress = (*env)->NewStringUTF(env, (char *)address);
    strClass = (*env)->FindClass(env, "Ljava/lang/String;");
    objArray = (*env)->NewObjectArray(env, 3, strClass, NULL);
    (*env)->SetObjectArrayElement(env, objArray, 0, strPrikey);
    (*env)->SetObjectArrayElement(env, objArray, 1, strPubkey);
    (*env)->SetObjectArrayElement(env, objArray, 2, strAddress);

    return objArray;
}


JNIEXPORT jobjectArray JNICALL Java_org_brewchain_core_crypto_jni_Crypto_recoverAccount(
        JNIEnv *env, jobject this, jlong context_, jstring prikey_)
{
    const void *context;
    const char *prikey;
    uint8_t pubkey[131];
    uint8_t address[41];
    jstring strPubkey;
    jstring strAddress;
    jclass  strClass;
    jobjectArray objArray;

    context = (const void *)(uintptr_t)context_;
    prikey = (*env)->GetStringUTFChars(env, prikey_, JNI_FALSE);
    recover_account(context, (uint8_t *)prikey, strlen(prikey), pubkey, 131, address, 41);
    (*env)->ReleaseStringUTFChars(env, prikey_, prikey);
    strPubkey = (*env)->NewStringUTF(env, (char *)pubkey);
    strAddress = (*env)->NewStringUTF(env, (char *)address);
    strClass = (*env)->FindClass(env, "Ljava/lang/String;");
    objArray = (*env)->NewObjectArray(env, 2, strClass, NULL);
    (*env)->SetObjectArrayElement(env, objArray, 0, strPubkey);
    (*env)->SetObjectArrayElement(env, objArray, 1, strAddress);

    return objArray;
}


JNIEXPORT jstring JNICALL Java_org_brewchain_core_crypto_jni_Crypto_signTransaction(
        JNIEnv *env, jobject this, jlong context_, jstring prikey_,
        jstring nonce_, jstring to_, jstring gasPrice_, jstring gasLimit_,
        jstring value_, jstring data_)
{
    const void *context;
    const char *prikey;
    const char *nonce;
    const char *to;
    const char *gasPrice;
    const char *gasLimit;
    const char *value;
    const char *data;
    uint8_t sigbuf[8192];

    context = (const void *)(uintptr_t)context_;

    prikey = (*env)->GetStringUTFChars(env, prikey_, JNI_FALSE);
    nonce = (*env)->GetStringUTFChars(env, nonce_, JNI_FALSE);
    to = (*env)->GetStringUTFChars(env, to_, JNI_FALSE);
    gasPrice = (*env)->GetStringUTFChars(env, gasPrice_, JNI_FALSE);
    gasLimit = (*env)->GetStringUTFChars(env, gasLimit_, JNI_FALSE);
    value = (*env)->GetStringUTFChars(env, value_, JNI_FALSE);
    data = (*env)->GetStringUTFChars(env, data_, JNI_FALSE);

    sign_transaction(context, prikey, nonce, to, gasPrice, gasLimit, value, data, sigbuf); 

    (*env)->ReleaseStringUTFChars(env, prikey_, prikey);
    (*env)->ReleaseStringUTFChars(env, nonce_, nonce);
    (*env)->ReleaseStringUTFChars(env, to_, to);
    (*env)->ReleaseStringUTFChars(env, gasPrice_, gasPrice);
    (*env)->ReleaseStringUTFChars(env, gasLimit_, gasLimit);
    (*env)->ReleaseStringUTFChars(env, value_, value);
    (*env)->ReleaseStringUTFChars(env, data_, data);

    return (*env)->NewStringUTF(env, (char *)sigbuf);
}


JNIEXPORT jint JNICALL Java_org_brewchain_core_crypto_jni_Crypto_verifySignature(
        JNIEnv *env, jobject this, jlong context_,jstring pubKey_, 
        jbyteArray msgHash_, jbyteArray sigData_)
{
    unsigned char *msgHash;
    unsigned char *sigData;

    const char *pubKey;
    int nResult =0;

    size_t msgLen;
    size_t sigLen;
    const void *context;

    context = (const void *)(uintptr_t)context_;

    pubKey = (*env)->GetStringUTFChars(env, pubKey_, JNI_FALSE);

    msgHash = (unsigned char *)(*env)->GetByteArrayElements(env, msgHash_, JNI_FALSE);
    msgLen = (size_t)(*env)->GetArrayLength(env, msgHash_);

    sigData = (unsigned char *)(*env)->GetByteArrayElements(env, sigData_, JNI_FALSE);
    sigLen = (size_t)(*env)->GetArrayLength(env, sigData_);

    nResult = verify_signature(context, pubKey ,msgHash, msgLen, sigData, sigLen);

    (*env)->ReleaseStringUTFChars(env, pubKey_, pubKey);

    return (jint)nResult;
}


JNIEXPORT jstring JNICALL Java_org_brewchain_core_crypto_jni_Crypto_signData(
        JNIEnv *env, jobject this, jlong context_, jstring prikey_,jstring data_)
{
    const void *context;
    const char *prikey;
   
    const char *data;
    uint8_t sigbuf[8192]={0};

    context = (const void *)(uintptr_t)context_;

    prikey = (*env)->GetStringUTFChars(env, prikey_, JNI_FALSE);
    data = (*env)->GetStringUTFChars(env, data_, JNI_FALSE);

    printf("data=%s\r\n", data);

    sign_Data(context, prikey, data, sigbuf); 

    (*env)->ReleaseStringUTFChars(env, prikey_, prikey);
    (*env)->ReleaseStringUTFChars(env, data_, data);

    return (*env)->NewStringUTF(env, (char *)sigbuf);
}



JNIEXPORT jstring JNICALL Java_org_brewchain_core_crypto_jni_Crypto_Datahash(
        JNIEnv *env, jobject this, jlong context_,jstring data_)
{
    const void *context;
    const char *data;
    uint8_t hashbuf[8192]={0};

    context = (const void *)(uintptr_t)context_;
    data = (*env)->GetStringUTFChars(env, data_, JNI_FALSE);

    Data_hash(context, data, hashbuf); 

    (*env)->ReleaseStringUTFChars(env, data_, data);

    return (*env)->NewStringUTF(env, (char *)hashbuf);
}



