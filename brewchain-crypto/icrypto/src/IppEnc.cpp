#include "icrypto.h"


void genKeyPair(ICKeyPair256 *kp,int len,Ipp32u *seed){

	unique_ptr<Ipp8u[]> sECP = autoStd_256_ECP();

	IppsECCPState* pECP = (IppsECCPState*)sECP.get(); 
	IppECResult eccResult; 

	unique_ptr<Ipp8u[]> agen = autoPRNG(len,seed);
	IppsPRNGState* pRandGen = (IppsPRNGState*)agen.get(); // 'external' PRNG 
	Ipp32u secp256r1_r[] = {0xC6325F51, 0xFAC23B9C, 0xA7179E84, 0xBCE6FAAD,0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}; 
	const int ordSize = sizeof(secp256r1_r)/sizeof(Ipp32u); 
	const int byteSize = sizeof(secp256r1_r); 

	// declare Signer's regular and ephemeral key pair 

	unique_ptr<Ipp8u[]> aregPrivate = autoBN(ordSize,0);
	IppsBigNumState* regPrivate = (IppsBigNumState*)aregPrivate.get();
	unique_ptr<Ipp8u[]> aregPublic = autoECP_256_Point(); 
	IppsECCPPointState* regPublic = (IppsECCPPointState*)aregPublic.get(); 

#ifdef __MACOS
	ippsECCPGenKeyPair(regPrivate, regPublic, pECP, ippsPRNGen, pRandGen);
#else
	ippsECCPGenKeyPair(regPrivate, regPublic, pECP, ippsPRNGenRDRAND, pRandGen);
#endif

	unique_ptr<Ipp8u[]> asignX = autoBN(ordSize,0);
	unique_ptr<Ipp8u[]> asignY = autoBN(ordSize,0);
   	IppsBigNumState* signX = (IppsBigNumState*)asignX.get();
   	IppsBigNumState* signY = (IppsBigNumState*)asignY.get();

	ippsECCPGetPoint(signX,signY,regPublic,pECP);


   	Type_BN("OP=",regPrivate);
   	Type_BN("OX=",signX);
   	Type_BN("OY=",signY);
   	dumpHex(regPublic);

   	IppsBigNumSGN sgn; 
   	int bnsize ;
   	ippsGet_BN(&sgn, &bnsize, (Ipp32u*)kp->p, regPrivate); 
	ippsGet_BN(&sgn, &bnsize, (Ipp32u*)kp->x, signX); 
	ippsGet_BN(&sgn, &bnsize, (Ipp32u*)kp->y, signY); 

   	dumpHex("kp.p==",kp->p,0,32);

   	//dumpHex(regPublic);
   	//dumpHex(regPublic);

   	// printf("Hex.regPrivate=");
    // dumpHex(kp->p,0,sizeof(kp->p));


}

bool fromPriKey(ICKeyPair256 *kp){
	unique_ptr<Ipp8u[]> sECP = autoStd_256_ECP();

	IppsECCPState* pECP = (IppsECCPState*)sECP.get(); 
	IppECResult eccResult; 

	unique_ptr<Ipp8u[]> agen = autoPRNG();
	IppsPRNGState* pRandGen = (IppsPRNGState*)agen.get(); // 'external' PRNG 
	Ipp32u secp256r1_r[] = {0xC6325F51, 0xFAC23B9C, 0xA7179E84, 0xBCE6FAAD,0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}; 
	const int ordSize = sizeof(secp256r1_r)/sizeof(Ipp32u); 
	const int byteSize = sizeof(secp256r1_r); 

	// declare Signer's regular and ephemeral key pair 

	unique_ptr<Ipp8u[]> aregPrivate = autoBN(ordSize,0);
	IppsBigNumState* regPrivate = (IppsBigNumState*)aregPrivate.get();


	ippsSet_BN(IppsBigNumPOS, ordSize,  (Ipp32u*)kp->p, regPrivate); 
	// define Signer's ephemeral key pair

	unique_ptr<Ipp8u[]> aregPublic = autoECP_256_Point(); 
	IppsECCPPointState* regPublic = (IppsECCPPointState*)aregPublic.get(); 
	if(ippsECCPPublicKey(regPrivate, regPublic, pECP)!=ippStsNoErr){
		return false;
	}

	unique_ptr<Ipp8u[]> asignX = autoBN(ordSize,0);
	unique_ptr<Ipp8u[]> asignY = autoBN(ordSize,0);
   	IppsBigNumState* signX = (IppsBigNumState*)asignX.get();
   	IppsBigNumState* signY = (IppsBigNumState*)asignY.get();

	ippsECCPGetPoint(signX,signY,regPublic,pECP);

   	Type_BN("OP=",regPrivate);
   	Type_BN("OX=",signX);
   	Type_BN("OY=",signY);
   	dumpHex(regPublic);

   	IppsBigNumSGN sgn; 
   	int bnsize ;
	ippsGet_BN(&sgn, &bnsize, (Ipp32u*)kp->x, signX); 
	ippsGet_BN(&sgn, &bnsize, (Ipp32u*)kp->y, signY); 

   	dumpHex("kp.p==",kp->p,0,32);

	return true;
}


bool signMessage(ICKeyPair256 *kp,Ipp8u *message){

	

	unique_ptr<Ipp8u[]> sECP = autoStd_256_ECP();

	IppsECCPState* pECP = (IppsECCPState*)sECP.get(); 
	IppECResult eccResult; 

	unique_ptr<Ipp8u[]> agen = autoPRNG();
	IppsPRNGState* pRandGen = (IppsPRNGState*)agen.get(); // 'external' PRNG 
	Ipp32u secp256r1_r[] = {0xC6325F51, 0xFAC23B9C, 0xA7179E84, 0xBCE6FAAD,0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}; 
	const int ordSize = sizeof(secp256r1_r)/sizeof(Ipp32u); 
	const int byteSize = sizeof(secp256r1_r); 
	unique_ptr<Ipp8u[]> apECPorder = autoBN(ordSize,0);

	IppsBigNumState* pECPorder = (IppsBigNumState*)apECPorder.get(); 
	 ippsBigNumInit(ordSize, pECPorder);

   	ippsSet_BN(IppsBigNumPOS, ordSize, (Ipp32u*)secp256r1_r, pECPorder); 

	unique_ptr<Ipp8u[]> aregPrivate = autoBN(ordSize,0);
	IppsBigNumState* regPrivate = (IppsBigNumState*)aregPrivate.get();
	ippsSet_BN(IppsBigNumPOS, ordSize,  (Ipp32u*)kp->p, regPrivate); 
	// define Signer's ephemeral key pair
	unique_ptr<Ipp8u[]> aregPublic = autoECP_256_Point();
 
	IppsECCPPointState* regPublic = (IppsECCPPointState*)aregPublic.get(); 


	unique_ptr<Ipp8u[]> asignX = autoBN(ordSize,0);
	unique_ptr<Ipp8u[]> asignY = autoBN(ordSize,0);
   	IppsBigNumState* signX = (IppsBigNumState*)asignX.get();
   	IppsBigNumState* signY = (IppsBigNumState*)asignY.get();
   	ippsSet_BN(IppsBigNumPOS, ordSize, (Ipp32u*)kp->x, signX); 
   	ippsSet_BN(IppsBigNumPOS, ordSize,  (Ipp32u*)kp->y, signY); 
	if(ippsECCPSetPoint(signX,signY,regPublic,pECP)!=ippStsNoErr){
		return false;
	}

   	Type_BN("OP=",regPrivate);
   	Type_BN("OX=",signX);
   	Type_BN("OY=",signY);
   	dumpHex("regPublic=",regPublic);

   ippsECCPCheckPoint(regPublic,&eccResult,pECP);

   if(eccResult!=ippECValid){
   		return false;
   }
   // cout << "CheckPoint: "<< ippsECCGetResultString(eccResult)<<endl;


   int size = (sizeof(message)-1+3)/4;
   // printf("message=%d, %ld=",size,sizeof(message));
   dumpHex("message=",(Ipp8u*)message,0,sizeof(message));
   
   unique_ptr<Ipp8u[]> apRandMsg = autoBN(size,0);

   IppsBigNumState* pRandMsg = (IppsBigNumState*)apRandMsg.get();

   ippsSetOctString_BN(message, sizeof(message)-1, pRandMsg);

   Type_BN("Big Number value is:\n", pRandMsg);

   IppsBigNumState* pMsg = newBN(ordSize, 0);            // msg to be signed 
   ippsMod_BN(pRandMsg, pECPorder, pMsg); 
   Type_BN("pMsg:=",pMsg);


	unique_ptr<Ipp8u[]> aephPrivate = autoBN(ordSize,0);
	IppsBigNumState* ephPrivate = (IppsBigNumState*)aephPrivate.get();

	unique_ptr<Ipp8u[]> aephPublic = autoECP_256_Point(); 
	IppsECCPPointState* ephPublic = (IppsECCPPointState*)aephPublic.get(); 

#ifdef __MACOS
	ippsECCPGenKeyPair(ephPrivate, ephPublic, pECP, ippsPRNGen, pRandGen);
#else
	ippsECCPGenKeyPair(ephPrivate, ephPublic, pECP, ippsPRNGenRDRAND, pRandGen);
#endif

	Type_BN("EOPRI=",ephPrivate);
	// printf("ephPublic,%d=,%ld=",byteSize,ordSize*sizeof(Ipp32u));
	dumpHex("ephPublic",ephPublic);

	ippsECCPSetKeyPair(ephPrivate, ephPublic, ippFalse, pECP); 

	unique_ptr<Ipp8u[]> asignedX = autoBN(ordSize,0);
	unique_ptr<Ipp8u[]> asignedY = autoBN(ordSize,0);
	IppsBigNumState* signedX = (IppsBigNumState*)asignedX.get();
	IppsBigNumState* signedY = (IppsBigNumState*)asignedY.get();

	if(ippsECCPSignDSA(pMsg, regPrivate, signedX, signedY, pECP)!=ippStsNoErr){
		return false;
	}

	// ippsECCPSetKeyPair(NULL, regPublic, ippTrue, pECP); 
	// ippsECCPVerifyDSA(pMsg, signedX, signedY, &eccResult,pECP);

	// cout << "CheckPoint: "<< ippsECCGetResultString(eccResult)<<endl;
	
	Type_BN("signedX=",signedX);
	Type_BN("signedY=",signedY);
	IppsBigNumSGN sgn; 
   	int bnsize ;
	ippsGet_BN(&sgn, &bnsize, (Ipp32u*)kp->s, signedX);
	ippsGet_BN(&sgn, &bnsize, (Ipp32u*)kp->a, signedY);
	return true;
}


bool ippSHA256(Ipp8u *msg,int len,Ipp8u *digest){

	int ctxSize; // context size// computing the context size
    ippsSHA256GetSize(&ctxSize);// context for the first half of message
    unique_ptr<Ipp8u[]> actx(new Ipp8u[ctxSize]);

    IppsSHA256State* ctx=(IppsSHA256State*)actx.get();// context initialization 
    
    ippsSHA256Init(ctx);// message example

    ippsSHA256Update(msg, len, ctx);// context for the entire message digest
    IppStatus status = ippsSHA256Final(digest, ctx);

    return status==ippStsNoErr;

}

bool verifyMessage(ICKeyPair256 *kp,Ipp8u *message){

	unique_ptr<Ipp8u[]> sECP = autoStd_256_ECP();

	IppsECCPState* pECP = (IppsECCPState*)sECP.get(); 
	IppECResult eccResult; 

	//unique_ptr<Ipp8u[]> agen = autoPRNG();
	//IppsPRNGState* pRandGen = (IppsPRNGState*)agen.get(); // 'external' PRNG 
	Ipp32u secp256r1_r[] = {0xC6325F51, 0xFAC23B9C, 0xA7179E84, 0xBCE6FAAD,0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}; 
	const int ordSize = sizeof(secp256r1_r)/sizeof(Ipp32u); 
	const int byteSize = sizeof(secp256r1_r); 
	unique_ptr<Ipp8u[]> apECPorder = autoBN(ordSize,0);

	IppsBigNumState* pECPorder = (IppsBigNumState*)apECPorder.get(); 
	ippsBigNumInit(ordSize, pECPorder);

   	ippsSet_BN(IppsBigNumPOS, ordSize, (Ipp32u*)secp256r1_r, pECPorder); 

	unique_ptr<Ipp8u[]> aregPublic = autoECP_256_Point(); 
	IppsECCPPointState* regPublic = (IppsECCPPointState*)aregPublic.get(); 

	unique_ptr<Ipp8u[]> asignX = autoBN(ordSize,0);
	unique_ptr<Ipp8u[]> asignY = autoBN(ordSize,0);
   	IppsBigNumState* signX = (IppsBigNumState*)asignX.get();
   	IppsBigNumState* signY = (IppsBigNumState*)asignY.get();
   	ippsSet_BN(IppsBigNumPOS, ordSize, (Ipp32u*)kp->x, signX); 
   	ippsSet_BN(IppsBigNumPOS, ordSize,  (Ipp32u*)kp->y, signY); 
	if(ippsECCPSetPoint(signX,signY,regPublic,pECP)!=ippStsNoErr){
		return false;
	}

   	Type_BN("OX=",signX);
   	Type_BN("OY=",signY);
   	dumpHex("regPublic=",regPublic);

   ippsECCPCheckPoint(regPublic,&eccResult,pECP);
	
   if(eccResult!=ippECValid){
   		return false;
   }
   // cout << "CheckPoint: "<< ippsECCGetResultString(eccResult)<<endl;


   int size = (sizeof(message)-1+3)/4;
   // printf("message=%d, %ld=",size,sizeof(message));
   dumpHex("message=",(Ipp8u*)message,0,sizeof(message));
   
   unique_ptr<Ipp8u[]> apRandMsg = autoBN(size,0);

   IppsBigNumState* pRandMsg = (IppsBigNumState*)apRandMsg.get();

   ippsSetOctString_BN(message, sizeof(message)-1, pRandMsg);

   Type_BN("Big Number value is:\n", pRandMsg);

   IppsBigNumState* pMsg = newBN(ordSize, 0);            // msg to be signed 
   ippsMod_BN(pRandMsg, pECPorder, pMsg); 
   Type_BN("pMsg:=",pMsg);



	ippsECCPSetKeyPair(NULL, regPublic, ippTrue, pECP); 

	unique_ptr<Ipp8u[]> asignedX = autoBN(ordSize,0);
	unique_ptr<Ipp8u[]> asignedY = autoBN(ordSize,0);
	IppsBigNumState* signedX = (IppsBigNumState*)asignedX.get();
	IppsBigNumState* signedY = (IppsBigNumState*)asignedY.get();
   	ippsSet_BN(IppsBigNumPOS, ordSize, (Ipp32u*)kp->s, signedX); 
   	ippsSet_BN(IppsBigNumPOS, ordSize,  (Ipp32u*)kp->a, signedY); 

	Type_BN("signedX=",signedX);
	Type_BN("signedY=",signedY);

	ippsECCPVerifyDSA(pMsg, signedX, signedY, &eccResult,pECP);
		
// #ifdef __DEBUG
// 		cout << "CheckPoint: "<< ippsECCGetResultString(eccResult)<<endl;
// #endif

	if(eccResult!=ippECValid){
   		return false;
	}
	return true;
// 	dumpHex("VerifySuccess=",(Ipp8u*)message,0,sizeof(message));

// //test..
// 	{
// 		unique_ptr<Ipp8u[]> sECP = autoStd_256_ECP();

// 		IppsECCPState* pECP = (IppsECCPState*)sECP.get(); 

// 		unique_ptr<Ipp8u[]> aTregPublic = autoECP_256_Point(); 
// 		IppsECCPPointState* TregPublic = (IppsECCPPointState*)aregPublic.get(); 
// 		IppStatus status=ippsECCPSetPoint(signedX,signedY,TregPublic,pECP);
// 		if(status==ippStsNoErr){
// 			dumpHex("DumpPublicOKOK=",(Ipp8u*)TregPublic,0,sizeof(TregPublic));

// 			unique_ptr<Ipp8u[]> asignX = autoBN(ordSize,0);
// 			unique_ptr<Ipp8u[]> asignY = autoBN(ordSize,0);
// 		   	IppsBigNumState* signX = (IppsBigNumState*)asignX.get();
// 		   	IppsBigNumState* signY = (IppsBigNumState*)asignY.get();

// 			ippsECCPGetPoint(signX,signY,regPublic,pECP);
// 		   	Type_BN("OX=",signX);
// 		   	Type_BN("OY=",signY);



// 		}else{
// 			printf("\nNOT OK::%s\n",ippcpGetStatusString(status));
// 		}

// 	}

	// return true;

}