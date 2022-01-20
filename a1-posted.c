//LIBRARIES
#include <stdio.h>
#include <string.h>

//GLOBAL CONSTANTS
#define MAX_BUF  256
#define IV 0b11001011

//HELPER FUNCTIONS

//Function that returns a byte's bit at the specified position.
unsigned char getBit(unsigned char a, int pos){
    return (a>>pos)&1;
}

//Function that sets a byte's bit at the specified position (converts it from 0 to 1).
unsigned char setBit(unsigned char a, int pos){
    a |= 1 << pos;
    return a;
}

//Function that clears a byte's bit at the specified position (converts it from 1 to 0).
unsigned char clearBit(unsigned char a, int pos){
    a &= ~(1 << pos);
    return a;
}

//Performs a left circular shift on the specified byte. Also takes in the # of positions being shifted.
unsigned char leftCircularShift(unsigned char a, int pos){
    
    //Array that'll keep track of the bits shifted out after the logical shift.
    int shiftedOut[pos];
    
    //Populates the array with bits that'll be shifted out.
    for (int i = 0; i < pos; i++){
        shiftedOut[i] = getBit(a,7-i);
    }

    //Peforms the logical shift.
    a = a << pos;

    //Enacts the 'circular' part of the circular shift, by putting in the shifted bits back in the byte, except on the other side.
    for (int i = 0; i < pos; i++){
        if (shiftedOut[i] != 0){
            a = setBit(a,pos-1-i);
        }
    }        
    return a;
}

//Performs a right circular shift on the specified byte. Also takes in the # of positions being shifted.
unsigned char rightCircularShift(unsigned char a, int pos){
    int shiftedOut[pos];
    int b;
 
    for (int i = 0; i < pos; i++){
        shiftedOut[i] = getBit(a,i);
    }

    //Performs the logical shift.
    a = a >> pos;
    
    //Enacts the 'circular' part of the circular shift, by putting in the shifted bits back in the byte, except on the other side.
    for (int i = 0; i < pos; i++){
        if (shiftedOut[i] != 0){
            a = setBit(a,7 - pos + 1 + i);
        }
    }        
    return a;
}

//Function that takes in a partial key & computes it's computed key.
unsigned char computeKey(unsigned char partial){

    //Iterates over the four least significant bits of the partial key.
    for (int i=0; i<4; i++) {
        int mirror = 7 - i;
        //Makes sure only to modify the key if the bit is 1 (Bits 4-7 are already equal to ).
        if (getBit(partial,i) != 0){
            partial = setBit(partial,mirror);
        }
    }
    return partial;
}

//Function that takes in a source byte & key, and returns the corresponding cipherbyte.
unsigned char encryptByte(unsigned char src, unsigned char k){
    
    unsigned char cp = 0;
    
    //Source byte performs a left circular shift by two bits.
    src = leftCircularShift(src,2);
    
    //Iterates over the empty cipherbyte, and sets/clears each bit to the X0R of the source byte's bit @ it's current position & the key's bit @ it's mirror position.
    for (int i=0; i<8; i++){
        if ((getBit(src,i) ^ getBit(k,7-i)) > 0){
            cp = setBit(cp,i);
        }
        else{
            cp = clearBit(cp,i);
        }
    }
    return cp;
}

//Function that takes in a cipherbyte & key, and returns the corresponding source byte (essentially the reverse of the encryption process).
unsigned char decryptByte(unsigned char ct, unsigned char k){
    
    unsigned char src = 0;
    
    //Iterates over the empty source byte, and sets/clears each bit to the X0R of the cipherbyte's bit @ it's current position & the key's bit @ it's mirror position.
    for (int i=0; i<8; i++){
        if ((getBit(ct,i) ^ getBit(k,7-i)) > 0){
            src = setBit(src,i);
        }
        else{
            src = clearBit(src,i);
        }
    }

    //Performs a right circular shift by two bits.
    src = rightCircularShift(src,2);

    return src; 
}

//Takes in a plaintext & a computed key, and encodes it's corresponding ciphertext. 
void encode(unsigned char *pt, unsigned char *ct, unsigned char k){
    unsigned char source;
    unsigned char prevCipherbyte;
    
    //First source byte is the plainbyte XOR'd with the initital value.
    source = pt[0] ^ IV;

    //Takes in the source byte & the key, and returns an encrypted cipherbyte.
    ct[0] = encryptByte(source,k);

    //Iterates over the plaintext.
    for (int i = 1; i < strlen(pt); i++){
        prevCipherbyte = ct[i-1];
        //Remaining source bytes are the corresponding plainbytes XOR'd with the previous cipherbytes.
        source = pt[i] ^ prevCipherbyte;

        //Encryption process once again.
        ct[i] = encryptByte(source,k);
    }
}

//Takes in a ciphertext & a computed key, and decode it's corresponding plaintext (essentially the reverse of the encoding process).
void decode(unsigned char *ct, unsigned char *pt, unsigned char k, int numBytes){
    unsigned char source;

    //Iterates over the ciphertext backwards and finds the source byte using a combination of the cipherbyte & computed key.
    for (int i = numBytes - 1; i > 0; i--){
        source = decryptByte(ct[i],k);

        //Sets the plainbyte to the source byte XOR'd with the previous cipherbyte.
        pt[i] = source ^ ct[i-1];
    }

    //Since there isn't a previous cipherbyte at this point, the 'first' plainbyte is the source byte XOR'd with the initial value.
    source = decryptByte(ct[0],k);
    pt[0] = source ^ IV;
}


int main()
{
  //Tracks the user's choice.
  char str[8];
  int  choice;

  //Our plain & ciphertexts.
  unsigned char plaintext[MAX_BUF];
  char cipherinput[MAX_BUF];
  unsigned char ciphertext[MAX_BUF];
  unsigned char* pt = &plaintext;
  char* ci = &cipherinput;
  unsigned char *ct = &ciphertext;
  
  int key;
  
  //Tracks the length of the ciphertext.
  int count = 0;

  //Tracks the sentinel value (the value that signals the end of the user's ciphertext input)
  int sentinelValue;

  //Encryption or decryption selection.
  printf("\nYou may:\n");
  printf("  (1) Encrypt a message \n");
  printf("  (2) Decrypt a message \n");
  printf("\n  what is your selection: ");
  fgets(str, sizeof(str), stdin);
  sscanf(str, "%d", &choice);

  switch (choice) {
    //Encryption process
    case 1:

        //Takes in the key (loops over the process untill a valid key is inputted).
        printf("\nEnter your key (must be a number from 1-15) below:\n");
        while ( scanf("%d",&key) == key < 1 || key > 15 ){
            printf("Not a valid key! Please enter a new one below:\n");}
        getchar();

        //Takes in the plaintext and puts it into an array of char.
        printf("\nEnter your plaintext below: (Hit enter when finished)\n");
        fgets(plaintext,MAX_BUF,stdin);
        
        //Encryption
        encode(pt,ct,computeKey(key));
        
        //Outputs encrypted ciphertext.
        printf("\n\nYour ciphertext has been computed:\n");
        for (int i = 0; i < strlen(plaintext); i++){
            printf("%03d ",ciphertext[i]);
        }
        break;

    //Decryption process
    case 2:
    
        //Takes in the key (loops over the process untill a valid key is inputted).
        printf("\nEnter your key (must be a number from 1-15) below:\n");
        while ( scanf("%d",&key) == key < 1 || key > 15 ){
            printf("Not a valid key! Please enter a new one below:\n");}
        getchar();

        //Takes in ciphertext and inputs it into a incomplete array of char.
        printf("\nEnter your ciphertext below: (Input -1 then hit enter when finished)\n");
        do {scanf("%d", &cipherinput[count++]); sentinelValue = cipherinput[count-1];} 
        while (sentinelValue != -1 && count < MAX_BUF);
        
        //Resizes said array.
        cipherinput[count];
        
        //Creates the actual ciphertext array (identical to previous one sans the sentinel value -1).
        count--;
        for (int i = 0; i < count; i++){
            ciphertext[i] = cipherinput[i];
        }
 
        //Decryption
        decode(ct,pt,computeKey(key),count);
        
        //Ouputs decrypted plaintext.
        printf("\n\nYour plaintext has been computed:\n");
        for (int i = 0; i < count; i++){
            printf("%c",plaintext[i]);
        }
        break;

    default:
      break;
  }

  return 0;
}