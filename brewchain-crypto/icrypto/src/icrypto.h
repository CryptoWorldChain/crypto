#include <stdio.h>
#include <iostream> 
#include <vector> 
#include <time.h>
#include <chrono>
#include <string> 
#include "ippcp.h" 
#include <memory.h>
#include <memory>
using namespace std; 

#define __NDEBUG
#define __MACOS


#ifndef _Included_ICRYPTO_DLL
#define _Included_ICRYPTO_DLL


class ICBignumber
{
public:
	Ipp32u	size;
	Ipp8u* data;

public:
	ICBignumber(int _size):size(0),data(NULL){
		size=_size;
		if(size>0)
		{
			data = new Ipp8u[size];
		}
	}
	~ICBignumber(){
		if(size>0&&data!=NULL)
		{
			delete []data;
			data=NULL;
		}
		// cout<<"~ICBignumber:"<<size<<endl;
	}

} ;

class ICKeyPair256
{
public:
	Ipp8u p[32];
	Ipp8u x[32];
	Ipp8u y[32];
	Ipp8u s[32];
	Ipp8u a[32];

	// unique_ptr<ICBignumber> p(new ICBignumber(32));//private key
	// unique_ptr<ICBignumber> x(new ICBignumber(32));//x point
	// unique_ptr<ICBignumber> y(new ICBignumber(32));//y point
	// unique_ptr<ICBignumber> s(new ICBignumber(32));//s rand sec
	// unique_ptr<ICBignumber> a(new ICBignumber(32));//s rand sec
public:
	ICKeyPair256(){
		
	}
	~ICKeyPair256(){
		// cout<<"~ICKeyPair256"<<endl;
	}
} ;

//tools

IppsBigNumState* newBN(int len, const Ipp32u* pData);
unique_ptr<Ipp8u[]> autoBN(int len, const Ipp32u* pData);

IppsBigNumState* newBN(int len, const Ipp32u* pData);

unique_ptr<Ipp8u[]> autoStd_256_ECP(void) ;
IppsECCPState* newStd_256_ECP(void) ;

IppsECCPPointState* newECP_256_Point(void) ;
unique_ptr<Ipp8u[]> autoECP_256_Point(void) ;
void initPRNG(IppsPRNGState* pCtx, int len = 0 ,const Ipp32u* pData=NULL);
IppsPRNGState* newPRNG(void) ;
unique_ptr<Ipp8u[]>autoPRNG( int len = 0 ,const Ipp32u* pData=NULL) ;

//helper

void dumpHex(const char * msg,Ipp8u *pData,int offset,int size);
void dumpHex(const char * msg,Ipp32u *pData,int offset,int size);
void dumpHex(const char * msg,IppsBigNumState *bignum);
void dumpHex(const char * msg,IppsECCPPointState *bignum);

void dumpHex(Ipp8u *pData,int offset,int size);
void dumpHex(Ipp32u *pData,int offset,int size);
void dumpHex(IppsBigNumState *bignum);
void dumpHex(IppsECCPPointState *bignum);

IppsBigNumState* Type_BN(const char* pMsg, const IppsBigNumState* pBN);



void octexToByte(Ipp8u*pData,char *HEXStr,int size);

void octexToByte(Ipp32u*pData,char *HEXStr,int size);
bool copyBN(ICBignumber ibn,const IppsBigNumState* pBN);


void genKeyPair(ICKeyPair256 *kp,int len=0,Ipp32u *seed=NULL);
bool fromPriKey(ICKeyPair256 *kp);
bool signMessage(ICKeyPair256 *kp,Ipp8u *pMsg);

bool verifyMessage(ICKeyPair256 *kp,Ipp8u *pMsg);

#endif

