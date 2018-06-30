#include "icrypto.h"

#include "hash-library/sha256.h"
#include "hash-library/sha3.h"

  
int main(void) 
{ 

   //SHA256 sha256;
   
   // for(int i=0;i<1;i++)
   {
      SHA256 sha256;
      //sha3("Hello");
      std::cout << sha256("Hello World") << std::endl;
   }

   //return 1;
   SHA3 sha3;
   std::cout << sha3("Hello World") << std::endl;

   ICKeyPair256 kp;
   genKeyPair(&kp);

   fromPriKey(&kp);
   // Type_BN("regPrivate=",(IppsBigNumState*)kp.p);
   // Type_BN("signX=",(IppsBigNumState*)kp.x);
   // Type_BN("signY=",(IppsBigNumState*)kp.y);
   printf("Hex.regPrivate=");
   dumpHex(kp.p,0,sizeof(kp.p));


   Ipp8u message[] = "hello cwv";


   bool signResult = signMessage(&kp,(Ipp8u*)message);


   bool verfiyResult = verifyMessage(&kp,(Ipp8u*)message);


   printf("KP.P=");dumpHex(kp.p,0,32);
   printf("KP.X=");dumpHex(kp.x,0,32);
   printf("KP.Y=");dumpHex(kp.y,0,32);
   printf("KP.S=");dumpHex(kp.s,0,32);
   printf("KP.V=");dumpHex(kp.a,0,32);


   printf("signResult=%d,verfiyResult=%d\n\n",signResult,verfiyResult);
   //ICKeyPair256 kp1;
   // printf("regPublic=");
   // dumpHex((IppsBigNumState*)kp->p.data);
   return 2;
   // define standard 256-bit EC 
   // unique_ptr<Ipp8u[]> sECP = autoStd_256_ECP();
   unique_ptr<Ipp8u[]> sECP = autoStd_256_ECP();

   IppsECCPState* pECP = (IppsECCPState*)sECP.get(); 
   IppECResult eccResult; 


   unique_ptr<Ipp8u[]> agen = autoPRNG();
   IppsPRNGState* pRandGen = (IppsPRNGState*)agen.get(); // 'external' PRNG 
   // IppsECCPPointState* newephPublic = (IppsECCPPointState*)autoECP_256_Point().get();
   // extract or use any other way to get order(ECP) 
   Ipp32u secp256r1_r[] = {0xC6325F51, 0xFAC23B9C, 0xA7179E84, 0xBCE6FAAD,0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}; 
   // printf("savesec=");dumpHex((Ipp8u*)&secp256r1_r,0,sizeof(secp256r1_r));
   IppStatus status = ippsPRNGen((Ipp32u*)secp256r1_r,256,pRandGen);
   printf("randsec=%s=",ippcpGetStatusString(status));dumpHex((Ipp8u*)&secp256r1_r,0,sizeof(secp256r1_r));

   const int ordSize = sizeof(secp256r1_r)/sizeof(Ipp32u); 
   IppsBigNumState* pECPorder = (IppsBigNumState*)autoBN(ordSize, secp256r1_r).get();
   // dumpHex((Ipp8u*)&secp256r1_r,0,sizeof(secp256r1_r));
   
   // define a message to be signed; let it be random, for example 
   // ICKeyPair256 kp ;
   // copyBN(kp.s,pECPorder);
   // printf("sec value=%ld=",sizeof(secp256r1_r)*sizeof(Ipp32u));
   // dumpHex((Ipp8u*)kp.s.data,0,kp.s.size);
   // Type_BN("sec value=", pECPorder);
   
   return 1;


} 

