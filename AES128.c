/*  ======================================================================== *

                                    주 의 사 항


    1. 구현은 다양한 방식으로 이뤄질 수 있음
    2. AES128(...) 함수의 호출과 리턴이 여러번 반복되더라도 메모리 누수가 생기지 않게 함
    3. AddRoundKey 함수를 구현할 때에도 파라미터 rKey는 사전에 선언된 지역 배열을 가리키도록 해야 함
       (정확한 구현을 위해서는 포인터 개념의 이해가 필요함)
    4. 배열의 인덱스 계산시 아래에 정의된 KEY_SIZE, ROUNDKEY_SIZE, BLOCK_SIZE를 이용해야 함
       (상수 그대로 사용하면 안됨. 예로, 4, 16는 안되고 KEY_SIZE/4, BLOCK_SIZE로 사용해야 함)

 *  ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include "AES128.h"
#include <string.h>
#define KEY_SIZE 16
#define ROUNDKEY_SIZE 176
#define BLOCK_SIZE 16

/* 기타 필요한 전역 변수 추가 선언 */
static const BYTE sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; 
static const BYTE rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
static const BYTE Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/* 기타 필요한 함수 추가 선언 및 정의 */
static BYTE getSBoxValue(BYTE snum)
{
  return sbox[snum];
}
static BYTE getRSBoxValue(BYTE rsnum){
    return rsbox[rsnum];
}
/*  <키스케줄링 함수>
 *   
 *  key         키스케줄링을 수행할 16바이트 키
 *  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간
 */
void expandKey(BYTE *key, BYTE *roundKey){
    // 모든 key 를 저장하게끔 하자!
    // key가 16개로 구성되있으니, 일단 key 를 어떻게 처리 할 것인가 
    // key 0 1 2 3 -> roundKey and key 0 1 2 3 using g and xor make 4 5 6 7 
    /* 추가 구현 */ 
    BYTE temp[BLOCK_SIZE/4];
    int i;
    BYTE k;
    for(i = 0; i<KEY_SIZE/4;i++){ // first 0 to 3 ; 
        roundKey[(i*(BLOCK_SIZE/4))+0] = key[(i*(BLOCK_SIZE/4))+0];
        roundKey[(i*(BLOCK_SIZE/4))+1] = key[(i*BLOCK_SIZE/4)+1];
        roundKey[(i*(BLOCK_SIZE/4))+2] = key[(i*BLOCK_SIZE/4)+2];                
        roundKey[(i*(BLOCK_SIZE/4))+3] = key[(i*BLOCK_SIZE/4)+3];
    }
        // inital 초기화 
    for(i = 4; i<ROUNDKEY_SIZE/4; ++i){
        temp[0]= roundKey[(i-1)*(BLOCK_SIZE/4)+0];
        temp[1]= roundKey[(i-1)*(BLOCK_SIZE/4)+1];
        temp[2]= roundKey[(i-1)*(BLOCK_SIZE/4)+2];
        temp[3]= roundKey[(i-1)*(BLOCK_SIZE/4)+3];
        if(i%4 == 0){ // w_4k using g ! 
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            // left rotation w_4(k-1)

            temp[0]= getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2]= getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);

            //sbox(left rotation (w_4(k-1))) = z_k


            temp[0] = temp[0]^Rcon[i/4]; // z_k xor rR const
        }
        roundKey[i*(BLOCK_SIZE/4)+0] = roundKey[(i-(BLOCK_SIZE/4))*(BLOCK_SIZE/4)+0]^temp[0];
        roundKey[i*(BLOCK_SIZE/4)+1] = roundKey[(i-(BLOCK_SIZE/4))*(BLOCK_SIZE/4)+1]^temp[1];
        roundKey[i*(BLOCK_SIZE/4)+2] = roundKey[(i-(BLOCK_SIZE/4))*(BLOCK_SIZE/4)+2]^temp[2];
        roundKey[i*(BLOCK_SIZE/4)+3] = roundKey[(i-(BLOCK_SIZE/4))*(BLOCK_SIZE/4)+3]^temp[3];
        //store round key; 
    }


}


/*  <SubBytes 함수>
 *   
 *  block   SubBytes 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
 *  mode    SubBytes 수행 모드
 */
 BYTE* subBytes(BYTE *block, int mode){
    /* 필요하다 생각하면 추가 선언 */
    int i;
    
    switch(mode){

        case ENC:
            
            /* 추가 구현 */
            for(i = 0 ; i<BLOCK_SIZE; i++){
                block[i] =getSBoxValue(block[i]);
            }
            
            break;

        case DEC:

            /* 추가 구현 */
            for(i = 0 ; i<BLOCK_SIZE;i++){
                block[i] = getRSBoxValue(block[i]);

            }           
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}


/*  <ShiftRows 함수>
 *   
 *  block   ShiftRows 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
 *  mode    ShiftRows 수행 모드
 */
BYTE* shiftRows(BYTE *block, int mode){ 

    /* 필요하다 생각하면 추가 선언 */   
    BYTE temp[2];
    int i;
            
    switch(mode){

        case ENC:
            
            /* 추가 구현 */
            temp[0] = block[1];
            block[1] = block[5];
            block[5] = block[9];
            block[9] = block[13];
            block[13] = temp[0];
            //------------------// second row
            temp[0] = block[2];
            temp[1] = block[6];
            block[2] = block[10];
            block[6] = block[14];
            block[10] = temp[0];
            block[14] = temp[1];
            // -------------------// third row
            temp[0] = block[15];
            block[15] = block[11];
            block[11] = block[7];
            block[7] = block[3];
            block[3] = temp[0];
            break;

        case DEC:
            /* 추가 구현 */
            temp[0] = block[13];
            block[13] = block[9];
            block[9] = block[5];
            block[5] = block[1];
            block[1] = temp[0];
            
            //------------------// second row
            temp[0] = block[2];
            temp[1] = block[6];
            block[2] = block[10];
            block[6] = block[14];
            block[10] = temp[0];
            block[14] = temp[1];
            // -------------------// third row
            temp[0] = block[3];
            block[3] = block[7];
            block[7] = block[11];
            block[11] = block[15];
            block[15] = temp[0];
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}


/*  <MixColumns 함수>
 *   
 *  block   MixColumns을 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
 *  mode    MixColumns의 수행 모드
 */
BYTE* mixColumns(BYTE *block, int mode){    
    BYTE temp1[BLOCK_SIZE/4];
    BYTE temp2[BLOCK_SIZE/4];
    BYTE temp3[BLOCK_SIZE/4];
    BYTE temp4[BLOCK_SIZE/4];
    BYTE temp5[BLOCK_SIZE/4];
    BYTE temp6[BLOCK_SIZE/4];
    BYTE temp7[BLOCK_SIZE/4];
    BYTE temp8[BLOCK_SIZE/4];
    BYTE temp9[BLOCK_SIZE/4];
    BYTE temp10[BLOCK_SIZE/4];
    BYTE temp11[BLOCK_SIZE/4];
    BYTE temp12[BLOCK_SIZE/4];
    BYTE temp13[BLOCK_SIZE/4];
    BYTE temp14[BLOCK_SIZE/4];

    BYTE high;
    int i;
    int j;
    /* 필요하다 생각하면 추가 선언 */   
    // 2 3 1 1  0 4  8 12
    // 1 2 3 1  1 5  9 13
    // 1 1 2 3  2 6 10 14
    // 3 1 1 2  3 7 11 15
    switch(mode){ 

        case ENC:
            /* 추가 구현 */
            // temp마다 shift 한 결과값 저장 
            for(j =0 ;j<BLOCK_SIZE/4;j++){
                for(i = 0;i<BLOCK_SIZE/4;i++){
                    temp1[i] = block[(BLOCK_SIZE/4)*j+i];
                    temp2[i] = block[(BLOCK_SIZE/4)*j+i]<<1;
                    high =(BYTE)((signed char)block[j*(BLOCK_SIZE/4)+i]>>7);
                    temp2[i] ^= 0x1b&high;
                    temp3[i] = temp1[i]^temp2[i];
             
               }
               block[(BLOCK_SIZE/4)*j+0] = temp2[0]^temp3[1]^temp1[2]^temp1[3];
               block[(BLOCK_SIZE/4)*j+1] = temp1[0]^temp2[1]^temp3[2]^temp1[3];
               block[(BLOCK_SIZE/4)*j+2] = temp1[0]^temp1[1]^temp2[2]^temp3[3];
               block[(BLOCK_SIZE/4)*j+3] = temp3[0]^temp1[1]^temp1[2]^temp2[3];
             }
            
            break;

        case DEC:
        // 14 11 13  9
        //  9 14 11 13
        // 13  9 14 11
        // 11 13  9 14 
            /* 추가 구현 */
            for(j=0 ; j<BLOCK_SIZE/4;j++){
                for(i =0;i<BLOCK_SIZE/4;i++){
                    temp1[i] = block[(BLOCK_SIZE/4)*j+i]; //원본 x 
                    temp2[i] = block[(BLOCK_SIZE/4)*j+i]<<1; // 2x ;
                    // tem2 -> carry remove
                    high =(BYTE)((signed char)block[j*(BLOCK_SIZE/4)+i]>>7);
                    temp2[i] ^= 0x1b&high;
                    temp3[i] = temp2[i]<<1; //2(2x) = 4x
                    high =(BYTE)((signed char)temp2[i]>>7);
                    temp3[i] ^= 0x1b&high;
                    temp4[i] = temp2[i]^temp1[i]; // 2x + x = 3x 
                    temp5[i] = temp3[i]<<1; //  2(2(2x))  =8x
                    high =(BYTE)((signed char)temp3[i]>>7);
                    temp5[i] ^= 0x1b&high;

                    temp8[i] = temp5[i]^temp1[i]; // 2(2(2x))+x = 9x;
                    temp6[i] = temp4[i]<<1; // 2(3x) = 6x;
                    high =(BYTE)((signed char)temp4[i]>>7);
                    temp6[i] ^= 0x1b&high;

                    temp7[i] = temp6[i]^temp1[i]; // 6x+x = 7x;
                    temp14[i] = temp7[i]<<1; //2(7x) = 14x;

                    high =(BYTE)((signed char)temp7[i]>>7);
                    temp14[i] ^= 0x1b&high;

                    temp9[i] = temp6[i]<<1; // 2(6x) = 12x;

                    high =(BYTE)((signed char)temp6[i]>>7);
                    temp9[i] ^= 0x1b&high;

                    temp12[i] = temp9[i]^temp1[i];// 12x+x = 13x;
                    temp11[i] = temp3[i]^temp1[i];//4x+x=5x
                    temp13[i] = temp11[i]<<1; //2(5x) = 10x 
                    high =(BYTE)((signed char)temp11[i]>>7);
                    temp13[i] ^= 0x1b&high;

                    temp10[i] = temp13[i]^temp1[i]; // 10x+x =11x

                }
                block[BLOCK_SIZE/4*j+0] = temp14[0]^temp10[1]^temp12[2]^temp8[3];
                block[BLOCK_SIZE/4*j+1] = temp8[0]^temp14[1]^temp10[2]^temp12[3];
                
                block[BLOCK_SIZE/4*j+2] = temp12[0]^temp8[1]^temp14[2]^temp10[3];
                block[BLOCK_SIZE/4*j+3] = temp10[0]^temp12[1]^temp8[2]^temp14[3]; 
               }
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}
/*  <AddRoundKey 함수>
 *   
 *  block   AddRoundKey를 수행할 16바이트 블록. 수행 결과는 해당 배열에 반영
 *  rKey    AddRoundKey를 수행할 16바이트 라운드키
 */
BYTE* addRoundKey(BYTE *block, BYTE *rKey){
int i;
    /* 추가 구현 */
    for(i=0;i<BLOCK_SIZE;i++){
        block[i] = block[i]^rKey[i]; 
    }

    return block;
}
/*  <128비트 AES 암복호화 함수>
 *  
 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
 *
 *  [ENC 모드]
 *  input   평문 바이트 배열
 *  output  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 *
 *  [DEC 모드]
 *  input   암호문 바이트 배열
 *  output  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 */

void AES128(BYTE *input, BYTE *output, BYTE *key, int mode){
    //setvbuf(stdout,NULL,_IONBF,0);
        memcpy(output,input,sizeof(BYTE)*KEY_SIZE);
    if(mode == ENC){
        int round =0;

        BYTE rKeys[ROUNDKEY_SIZE];
        expandKey(key,rKeys);
        addRoundKey(output,rKeys);
        for (round =1;round<10;++round){
            subBytes(output,ENC);
            shiftRows(output,ENC);
            mixColumns(output,ENC);
            addRoundKey(output,rKeys+(round*KEY_SIZE));
        }
            subBytes(output,ENC);
            shiftRows(output,ENC);
            addRoundKey(output,rKeys+(round*KEY_SIZE));

        /* 추가 작업이 필요하다 생각하면 추가 구현 */    

    }else if(mode == DEC){

        int round = 10;
        BYTE rKeys[ROUNDKEY_SIZE];
        expandKey(key,rKeys);
        addRoundKey(output,rKeys+(round*KEY_SIZE));
        for (round = 9; round>0;--round){
            subBytes(output,DEC);
            shiftRows(output,DEC);
            mixColumns(rKeys+(round*KEY_SIZE),DEC);
            mixColumns(output,DEC);
            addRoundKey(output,rKeys+(round*KEY_SIZE)); // add round key 를 mix column 해주어야 한다. 

        }
            subBytes(output,DEC);
            shiftRows(output,DEC);
            addRoundKey(output,rKeys);
        /* 추가 작업이 필요하다 생각하면 추가 구현 */    

    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}
