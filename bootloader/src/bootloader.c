/*
 * bootloader.c
 *
 * If Port B Pin 2 (PB2 on the protostack board) is pulled to ground the
 * bootloader will wait for data to appear on UART1 (which will be interpretted
 * as an updated firmware package).
 *
 * If the PB2 pin is NOT pulled to ground, but
 * Port B Pin 3 (PB3 on the protostack board) is pulled to ground, then the
 * bootloader will enter flash memory readback mode.
 *
 * If NEITHER of these pins are pulled to ground, then the bootloader will
 * execute the application from flash.
 *
 * If data is sent on UART for an update, the bootloader will expect that data
 * to be sent in frames. A frame consists of two sections:
 * 1. Two bytes for the length of the data section
 * 2. A data section of length defined in the length section
 *
 * [ 0x02 ]  [ variable ]
 * ----------------------
 * |  Length |  Data... |
 *
 * Frames are stored in an intermediate buffer until a complete page has been
 * sent, at which point the page is written to flash. See program_flash() for
 * information on the process of programming the flash memory. Note that if no
 * frame is received after 2 seconds, the bootloader will time out and reset.
 *
 */

#include <avr/io.h>
#include <stdint.h>
#include <stdio.h>
#include <util/delay.h>
#include "uart.h"
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>

#include <string.h>
#include "aes.h"

#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)

void program_flash(uint32_t page_address, unsigned char *data);
void load_firmware(void);
void boot_firmware(void);
void readback(void);
void cbc_decrypt_firmware(aes256_ctx_t *ctx, uint8_t *pBlock, uint8_t *data);
void cbc_encrypt_firmware(aes256_ctx_t *ctx, uint8_t *pBlock, uint8_t *data);
int cst_time_memcmp_safest1(const void *m1, const void *m2, size_t n);


uint16_t fw_size EEMEM = 0;
uint16_t fw_version EEMEM = 0;
uint16_t bootStatus EEMEM = 0;

const unsigned char  FW_KEY[32] PROGMEM  = FIRMWARE_KEY;
const unsigned char RB_PASS[32]  PROGMEM = READBACK_PASSWORD;
const unsigned char M_KEY[32]  PROGMEM = MAC_KEY;

int main(void)
{
    // Init UART1 (virtual com port)
    UART1_init();

    UART0_init();
    wdt_reset();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);

    // If jumper is present on pin 2, load new firmware.
    if(!(PINB & (1 << PB2)))
    {
        UART1_putchar('U');
        load_firmware();
    }
    else if(!(PINB & (1 << PB3)))
    {
        UART1_putchar('R');
        readback();
    }
    else
    {
        UART1_putchar('B');
        boot_firmware();
    }
} // main

/*
 * Interface with host readback tool.
 */
void readback(void)
{
    unsigned char blockBuf[16];
    uint8_t iv[16];
    uint8_t blockIndex = 0;
    unsigned char readbackPass[32];
    memcpy_PF(readbackPass, pgm_get_far_address(RB_PASS),32);
    aes256_ctx_t ctx;

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    wdt_reset();

    aes256_init(readbackPass,&ctx);

    UART1_putchar(OK); //tell readback tool it's done setting up

    //retrieve the iv
    for(int i = 0; i < 16; i++){
        wdt_reset();
        iv[i] = UART1_getchar();
      }

    UART1_putchar(OK);

    // Read in start address (4 bytes).
    uint32_t start_addr = ((uint32_t)UART1_getchar()) << 24;
    start_addr |= ((uint32_t)UART1_getchar()) << 16;
    start_addr |= ((uint32_t)UART1_getchar()) << 8;
    start_addr |= ((uint32_t)UART1_getchar());

    wdt_reset();

    // Read in size (4 bytes).
    uint32_t size = ((uint32_t)UART1_getchar()) << 24;
    size |= ((uint32_t)UART1_getchar()) << 16;
    size |= ((uint32_t)UART1_getchar()) << 8;
    size |= ((uint32_t)UART1_getchar());

    wdt_reset();

    if (size % 16 != 0){ //check if size is a multiple of 16
      UART1_putchar(ERROR);
      while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
    }


    // Read the memory out to UART1.
    for(uint32_t addr = start_addr; addr < start_addr + size; ++addr)
    {
        // Read a byte from flash.
        unsigned char byte = pgm_read_byte_far(addr);
        wdt_reset();
        blockBuf[blockIndex] = byte;

        //Encrypt the message
        if (blockIndex == 15){
          cbc_encrypt_firmware(&ctx,iv,blockBuf);
          wdt_reset();
          memcpy(iv,blockBuf,16);
          blockIndex = 0;

          //Write out the value of blockBuf
          for(int i=0;i<16;i++){
            wdt_reset();
            UART1_putchar(blockBuf[i]);
          }
        }
        wdt_reset();
        blockIndex++;
    }
    while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
}


/*
 * Load the firmware into flash.
 */
 void load_firmware(void)
 {
     unsigned char previousBlock[16];
     unsigned char tempBlock[16];
     int frame_length = 0;
     unsigned char rcv = 0;
     unsigned char status = 0;
     unsigned char data[SPM_PAGESIZE]; // SPM_PAGESIZE is the size of a page.
     unsigned int data_index = 0;
     unsigned int page = 0;
     uint16_t version = 0;
     uint16_t size = 0;
     unsigned char fw_iv[16];
     unsigned char firmKey[32];
     unsigned char mac_iv[16];
     unsigned char macKey[32];
     unsigned char mac[16];
     unsigned char macBuf[SPM_PAGESIZE];
     uint8_t metaMacBuf[16];
     uint8_t meta_mac[16];
     uint8_t padding = 0x0c;
     uint8_t macVerified = 0;
     int pageNumber = 0;
     aes256_ctx_t encCtx;
     aes256_ctx_t decCtx;

     memcpy_PF(firmKey, pgm_get_far_address(FW_KEY),32);
     memcpy_PF(macKey, pgm_get_far_address(M_KEY),32);

     aes256_init(firmKey, &decCtx);
     aes256_init(macKey, &encCtx);

     //set mac iv to all zeros
     memset(mac_iv,0,16);

     // Start the Watchdog Timer
     wdt_enable(WDTO_2S);

     /* Wait for data */
     while(!UART1_data_available())

     {
         __asm__ __volatile__("");
     }

     eeprom_update_word(&bootStatus, 0); //The board won't boot if the update doesn't end cleanly

     // Get version.
     rcv = UART1_getchar();
     version = (uint16_t)rcv << 8;
     metaMacBuf[0] = rcv;
     rcv = UART1_getchar();
     version |= (uint16_t)rcv;
     metaMacBuf[1] = rcv;

     wdt_reset();

     // Get size.
     rcv = UART1_getchar();
     size = (uint16_t)rcv << 8;
     metaMacBuf[2] = rcv;
     rcv = UART1_getchar();
     size |= (uint16_t)rcv;
     metaMacBuf[3] = rcv;

     UART1_putchar(OK); // Acknowledge the metadata.

     //retrieve the metadata mac
     for(int i = 0; i < 16; i++){
         wdt_reset();
         meta_mac[i] = UART1_getchar();
       }

      //form the metadata mac buffer for use in metadata mac calculation
      for(int i = 4; i <16;i++){
        wdt_reset();
        metaMacBuf[i] = padding;
      }

      //calculate the metadata mac
      wdt_reset();
      cbc_encrypt_firmware(&encCtx,mac_iv,metaMacBuf);

      //compare mac values
       if (cst_time_memcmp_safest1(meta_mac,metaMacBuf,16) == 0){
         wdt_reset();
         UART1_putchar(OK);
       }

       else{
         UART1_putchar(ERROR); // Mac verification failure
         // Wait for watchdog timer to reset.
         while(1)
         {
             __asm__ __volatile__("");
         }
       }

     // Compare to old version and abort if older (note special case for version
     // 0).
     if (version != 0 && version < eeprom_read_word(&fw_version))
     {
         UART1_putchar(ERROR); // Reject the metadata.
         // Wait for watchdog timer to reset.
         while(1)
         {
             __asm__ __volatile__("");
         }
     }
     else if(version != 0)
     {
         // Update version number in EEPROM.
         wdt_reset();
         eeprom_update_word(&fw_version, version);
     }

     // Write new firmware size to EEPROM.
     if (size <= 30000){ //check that the size doesn't exceed the max size of 30kb
     wdt_reset();
     eeprom_update_word(&fw_size, size);
     wdt_reset();
     }
     else{ //if size is too large
       UART1_putchar(ERROR); // Reject the size
       // Wait for watchdog timer to reset.
       while(1)
       {
           __asm__ __volatile__("");
       }
     }
     wdt_reset();

     UART1_putchar(OK); // Acknowledge the metadata.

     //program the iv into memory
     for(int i = 0; i < 16; i++){
         wdt_reset();
         fw_iv[i] = UART1_getchar();
       }

     //set previousblock to the value of iv
     memcpy(previousBlock,fw_iv,16);

     wdt_reset();
     UART1_putchar(OK); // Acknowledge the iv

     //program cipher mac into memory
     for(int i = 0; i < 16; i++){
         wdt_reset();
         mac[i] = UART1_getchar();
       }


      wdt_reset();
      UART1_putchar(OK); // Acknowledge the cipherMac


     /* Loop here until you can get all your characters and stuff */
     while(1)
     {
       status = UART1_getchar();
       if (status == 0x00){
           wdt_reset();
           // Get two bytes for the length.
           rcv = UART1_getchar();
           frame_length = (int)rcv << 8;
           rcv = UART1_getchar();
           frame_length += (int)rcv;

           UART0_putchar((unsigned char)rcv);
           wdt_reset();

           // Get the number of bytes specified
           for(int i = 0; i < frame_length; ++i){
               wdt_reset();
               data[data_index] = UART1_getchar();
               data_index += 1;
           } //for

           // If we filed our page buffer, program it
           if(data_index == SPM_PAGESIZE || frame_length == 0 || frame_length == 1)
           {
               wdt_reset();

               memcpy(macBuf,data,SPM_PAGESIZE);

               //remeber the value of the ciphertext
               for(int i=0;i<SPM_PAGESIZE;i=i+16){
                 wdt_reset();
                 //encrypt firmware to check MAC
                 cbc_encrypt_firmware(&encCtx,mac_iv,macBuf+i);
                 memcpy(mac_iv, macBuf+i, 16);


                 //decrypt firmware
                 memcpy(tempBlock,data+i,16);
                 cbc_decrypt_firmware(&decCtx,previousBlock,data+i);
                 memcpy(previousBlock,tempBlock,16);

               }
               //flash the decrypted firmware
               program_flash(page, data);
               page += SPM_PAGESIZE;
               data_index = 0;
               pageNumber++;

   #if 1
               // Write debugging messages to UART0.
               UART0_putchar('P');
               UART0_putchar(page>>8);
               UART0_putchar(page);
   #endif
               wdt_reset();
           } // if

         UART1_putchar(OK); // Acknowledge the frame.
       } //if status


       else{

         for (int i=0;i<SPM_PAGESIZE;i=i+16){
           if (cst_time_memcmp_safest1(mac,macBuf + i,16) == 0){ //check if the mac values match
             eeprom_update_word(&bootStatus, 1); //sets the value of boot status to one in memory
             macVerified = 1;
             UART1_putchar(OK);
             break;
           }
         }

         //MAC verification failure, erase all pages
         if (macVerified != 1){
           // Fill pageBuffer with 0xFF
    			for(int i = 0; i < SPM_PAGESIZE; i++) {
    				data[i] = 0xFF;
    			}
           //erase firmware in memory
           for(int j = 0; j < pageNumber; j++) {
     				program_flash(j*SPM_PAGESIZE,data);
     			}
          //tell fw_update there was a problem verifying mac
           UART1_putchar(ERROR);
         }
       }
     } // while(1)
   }


/*
 * Ensure the firmware is loaded correctly and boot it up.
 */
void boot_firmware(void)
{

  if(eeprom_read_word(&bootStatus) != 1){ //check if mac has been verified
      while(1) __asm__ __volatile__(""); //wait for watchdog timer to reset
  }

    // Write out the release message.
    uint8_t cur_byte;
    uint32_t addr = (uint32_t)eeprom_read_word(&fw_size);

    // Reset if firmware size is 0 (indicates no firmware is loaded).
    if(addr == 0)
    {
        // Wait for watchdog timer to reset.
        while(1) __asm__ __volatile__("");
    }

    wdt_reset();

    // Write out release message to UART0.
    do
    {
        cur_byte = pgm_read_byte_far(addr);
        UART0_putchar(cur_byte);
        ++addr;
    } while (cur_byte != 0);

    // Stop the Watchdog Timer.
    wdt_reset();
    wdt_disable();

    /* Make the leap of faith. */
    asm ("jmp 0000");
}


/*
 * To program flash, you need to access and program it in pages
 * On the atmega1284p, each page is 128 words, or 256 bytes
 *
 * Programing involves four things,
 * 1. Erasing the page
 * 2. Filling a page buffer
 * 3. Writing a page
 * 4. When you are done programming all of your pages, enable the flash
 *
 * You must fill the buffer one word at a time
 */
void program_flash(uint32_t page_address, unsigned char *data)
{
    int i = 0;

    boot_page_erase_safe(page_address);

    for(i = 0; i < SPM_PAGESIZE; i += 2)
    {
        uint16_t w = data[i];    // Make a word out of two bytes
        w += data[i+1] << 8;
        boot_page_fill_safe(page_address+i, w);
    }

    boot_page_write_safe(page_address);
    boot_rww_enable_safe(); // We can just enable it after every program too
}


void cbc_decrypt_firmware(aes256_ctx_t *ctx, uint8_t *pBlock, uint8_t *data){
  //decrypt ciphertext block
  aes256_dec(data, ctx);
  //xor ciphertext with previous block/iv
  for(int i =0; i < 16; ++i){
    data[i] ^= pBlock[i];
  }
}

void cbc_encrypt_firmware(aes256_ctx_t *ctx, uint8_t *pBlock, uint8_t *data){
  //xor plaintext with previous block/iv
  for(int i =0; i < 16; ++i){
    data[i] ^= pBlock[i];
  }
  //encrypt ciphertext block
  aes256_enc(data, ctx);
}

int cst_time_memcmp_safest1(const void *m1, const void *m2, size_t n)
{
    const unsigned char *pm1 = (const unsigned char*)m1;
    const unsigned char *pm2 = (const unsigned char*)m2;
    int res = 0, diff;
    if (n > 0) {
        do {
            --n;
            diff = pm1[n] - pm2[n];
            res = (res & (((diff - 1) & ~diff) >> 8)) | diff;
        } while (n != 0);
    }
    return ((res - 1) >> 8) + (res >> 8) + 1;
}
