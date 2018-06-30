#include "icrypto.h"

void dumpHex(const char * msg,Ipp8u *pData,int offset,int size){
    #ifdef __DEBUG
    printf("%s",msg);
    dumpHex(pData,offset,size);

    #endif
}
void dumpHex(Ipp8u *pData,int offset,int size){
      #ifdef __DEBUG

      int i;
      int end =  offset + size;
      printf("0x");
      for (i = offset; i < end; i++)
      {
          printf("%02X", pData[i]);
      }
      printf("\n"); 
      #endif
}

void dumpHex(Ipp32u *pData,int offset,int size){
      #ifdef __DEBUG

      int i;
      int end =  offset + size;
      // printf("0x");
      for (i = offset; i < end; i++)
      {
          printf("0x%08X,", pData[i]);
      }
      printf("\n");


      #endif
}

void octexToByte(Ipp8u*pData,char *HEXStr,int size){
   int n;   
   for(int i = 0; i < size; i++) {
        sscanf(HEXStr+2*i, "%2X", &n);
        pData[i] = (char)n;
    }
}

void octexToByte(Ipp32u*pData,char *HEXStr,int size){
   Ipp32u n;   
   for(int i = 0; i < size; i++) {
        sscanf(HEXStr+8*i, "%8X", &n);
        pData[i] = n;
    }
}

void dumpHex(const char * msg,IppsBigNumState *bignum){
    #ifdef __DEBUG
    printf("%s",msg);
    dumpHex(bignum);
    #endif
}


void dumpHex(IppsBigNumState *bignum){
   #ifdef __DEBUG

   int size ;
   ippsGetSize_BN(bignum,&size);
   size = size;
   printf("bignumsize=%d:",size);
   dumpHex((Ipp32u*)bignum,0,size);
   #endif
}

void dumpHex(const char * msg,IppsECCPPointState *bignum){
    #ifdef __DEBUG

    printf("%s",msg);
    dumpHex(bignum);

    #endif
}
void dumpHex(IppsECCPPointState *bignum){
   int size ;
   ippsECCPPointGetSize(256,&size);
   dumpHex((Ipp8u*)bignum,0,size);
}


unique_ptr<Ipp8u[]> autoBN(int len, const Ipp32u* pData) {
   int ctxSize; 
   ippsBigNumGetSize(len, &ctxSize); 
   unique_ptr<Ipp8u[]> pn(new Ipp8u[ctxSize]);
   IppsBigNumState* pBN = (IppsBigNumState*)pn.get(); 
   ippsBigNumInit(len, pBN);
   if(pData) 
      ippsSet_BN(IppsBigNumPOS, len, pData, pBN); 
   return move(pn); 
}
  
IppsBigNumState* newBN(int len, const Ipp32u* pData) 
{ 
   int ctxSize; 
   ippsBigNumGetSize(len, &ctxSize); 
   IppsBigNumState* pBN = (IppsBigNumState*)( new Ipp8u [ctxSize] ); 
   ippsBigNumInit(len, pBN); 
   if(pData) 
      ippsSet_BN(IppsBigNumPOS, len, pData, pBN); 
   return pBN; 
} 
  


IppsBigNumState* Type_BN(const char* pMsg, const IppsBigNumState* pBN){ // size of Big Number
    #ifdef __DEBUG
      int size;
      ippsGetSize_BN(pBN, &size);
      Ipp8u* bnValue = new Ipp8u [size*4];       
      // extract Big Number value and convert it to the string presentation Ipp8u* bnValue = new Ipp8u [size*4];
      ippsGetOctString_BN(bnValue, size*4, pBN);
      // type header
      if(pMsg)
         cout<<pMsg;
      // type value
      //IppsBigNumState* newsignX = newBN(size,0); 
      // ippsSetOctString_BN(bnValue, size*4, newsignX);
      dumpHex(bnValue,0,size*4);
      //for(int n=0; n<size*4; n++)
      // cout<<hex<<setfill('0')<<setw(2)<<(int)bnValue[n]; cout<<endl;
      delete [] bnValue; 

      // return newsignX;
    #endif

    return NULL;

}

bool copyBN(ICBignumber ibn,const IppsBigNumState* pBN){ // size of Big Number
    int size;
    ippsGetSize_BN(pBN, &size);
    if(size*4 != ibn.size ){
      return false;
    }else{
      ippsGetOctString_BN(ibn.data, size*4, pBN);
    }
    return true;
}


unique_ptr<Ipp8u[]> autoStd_256_ECP(void) 
{ 
   int ctxSize; 
   ippsECCPGetSize(256, &ctxSize); 
   unique_ptr<Ipp8u[]> pn(new Ipp8u[ctxSize]);
   IppsECCPState* pCtx = (IppsECCPState*)pn.get();
   ippsECCPInit(256, pCtx); 
   ippsECCPSetStd(IppECCPStd256r1, pCtx); 
   return move(pn); 
} 
  

IppsECCPState* newStd_256_ECP(void) 
{ 
   int ctxSize; 
   ippsECCPGetSize(256, &ctxSize); 
   IppsECCPState* pCtx = (IppsECCPState*)( new Ipp8u [ctxSize] ); 
   ippsECCPInit(256, pCtx); 
   ippsECCPSetStd(IppECCPStd256r1, pCtx); 
   return pCtx; 
} 
  
 IppsECCPPointState* newECP_256_Point(void) 
{ 
   int ctxSize; 
   ippsECCPPointGetSize(256, &ctxSize); 
   IppsECCPPointState* pPoint = (IppsECCPPointState*)( new Ipp8u [ctxSize] ); 
   ippsECCPPointInit(256, pPoint); 
   return pPoint; 
} 


unique_ptr<Ipp8u[]> autoECP_256_Point(void)
{ 
   int ctxSize; 
   ippsECCPPointGetSize(256, &ctxSize); 
    unique_ptr<Ipp8u[]> pn(new Ipp8u[ctxSize]);
   IppsECCPPointState* pPoint = (IppsECCPPointState*)pn.get();
   // IppsECCPPointState* pPoint = (IppsECCPPointState*)( new Ipp8u [ctxSize] ); 
   ippsECCPPointInit(256, pPoint); 
   return move(pn); 
} 



void initPRNG(IppsPRNGState* pCtx, int len ,const Ipp32u* pData) 
{ 
   // Ipp8u *data = new Ipp8u[sizeof(long)*2];
   if(pData==NULL){
    #ifdef __MACOS
         clock_t start = clock();
         std::chrono::milliseconds epoch = std::chrono::duration_cast< std::chrono::milliseconds >(
              std::chrono::system_clock::now().time_since_epoch()
          );
         long count = epoch.count();
         int size = sizeof(long)*2;
         unique_ptr<Ipp8u[]> data(new Ipp8u[size]);
         memcpy(data.get(),&count,sizeof(long));
         memcpy(&data.get()[sizeof(long)],&start,sizeof(long));
            dumpHex(data.get(),0,size);

          IppsBigNumState *seedbn=(IppsBigNumState*)autoBN(size/4,(Ipp32u*)data.get()).get();
          ippsPRNGSetSeed(seedbn, pCtx);
    #endif
         // printf("%ld micro seconds, tick %ld since the epoch began:%ld:\n", (long)epoch.count(),(long)start,sizeof(long));      
    }else{
       IppsBigNumState *seedbn=(IppsBigNumState*)autoBN(len,pData).get();
       ippsPRNGSetSeed(seedbn, pCtx);
    }




   // dumpHex("seednd=",seedbn);

   
   // delete [] (Ipp8u*)seedbn; 
   // delete [] (Ipp8u*)data; 
   

} 


IppsPRNGState* newPRNG(void) 
{ 
   int ctxSize; 
   ippsPRNGGetSize(&ctxSize); 
   IppsPRNGState* pCtx = (IppsPRNGState*)( new Ipp8u [ctxSize] ); 
   ippsPRNGInit(256, pCtx);
   initPRNG(pCtx);
   return pCtx; 
} 

unique_ptr<Ipp8u[]> autoPRNG(int size ,const Ipp32u* pData) 
{ 
   int ctxSize; 
   ippsPRNGGetSize(&ctxSize); 
   // IppsPRNGState* pCtx = (IppsPRNGState*)( new Ipp8u [ctxSize] ); 
   unique_ptr<Ipp8u[]> pn(new Ipp8u[ctxSize]);
   IppsPRNGState* pCtx = (IppsPRNGState*)pn.get();
   ippsPRNGInit(256, pCtx);
   initPRNG(pCtx,size,pData);
   return move(pn); 
} 

