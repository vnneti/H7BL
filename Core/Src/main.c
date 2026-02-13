/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "mbedtls.h"
#include <stdbool.h>
#include <stdint.h>
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef struct
{
    uint32_t ActiveBankFlag;      // 0 = Bank0 aktiv, 1 = Bank1 aktiv
    uint32_t UpdateReadyFlag;     // 0 = kein Update, 1 = OTA Firmware fertig in inaktiver Bank
    uint8_t  AES_Key[16];         // optional
    uint8_t  SignatureBank0[64];  // ECDSA Signatur der Firmware in Bank0
    uint8_t  SignatureBank1[64];  // ECDSA Signatur der Firmware in Bank1
    uint8_t  PublicKey[64];       // X9.62 unkomprimierter öffentlicher Key (32B X + 32B Y)
    uint32_t FirmwareVersion;      // optional
    uint8_t  Reserved[128*1024 - 4 - 4 - 16 - 64 - 64 - 64 - 4]; // Rest des 128 KB Sektors
} UserData;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define BOOTLOADER_BASE_ADDR   0x08000000
#define APPLICATION_BANK0_ADDR 0x08020000
#define APPLICATION_BANK1_ADDR 0x08100000
#define FIRMWARE_SIZE 0xE0000
#define USER_DATA_ADDR         0x081D0000
#define USER_DATA_SECTOR_SIZE  (128*1024)
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

COM_InitTypeDef BspCOMInit;
__IO uint32_t BspButtonState = BUTTON_RELEASED;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MPU_Config(void);
static void MX_GPIO_Init(void);
/* USER CODE BEGIN PFP */
static void JumpToApplication(uint32_t addr);
static bool ValidateFirmware(uint32_t addr, uint8_t* signature);
static void FlashWriteUserData(uint32_t addr, UserData *user);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
static void JumpToApplication(uint32_t addr)
{
    uint32_t appStack = *(volatile uint32_t*)addr;
    uint32_t appResetHandler = *(volatile uint32_t*)(addr + 4);

    __disable_irq();

    __set_MSP(appStack);

    void (*appEntry)(void) = (void (*)(void))appResetHandler;
    appEntry();
}


static bool ValidateFirmware(uint32_t addr, uint8_t* signature)
{
	uint8_t hash[32];

	// 1️⃣ SHA256 berechnen
	mbedtls_sha256_context sha;
	mbedtls_sha256_init(&sha);
	mbedtls_sha256_starts_ret(&sha, 0);
	mbedtls_sha256_update_ret(&sha, (unsigned char*)addr, FIRMWARE_SIZE);
	mbedtls_sha256_finish_ret(&sha, hash);
	mbedtls_sha256_free(&sha);
	mbedtls_ecdsa_context ecdsa;
	mbedtls_ecdsa_init(&ecdsa);
	int ret = mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1);
	if (ret != 0)
	   goto cleanup;



    const unsigned char pub_key[] = {
      0x36, 0x20, 0x28, 0x77, 0x93, 0x2e, 0x51, 0x3b, 0x72, 0xfd, 0x8c, 0x21,
      0xe9, 0x18, 0x0a, 0xb9, 0x05, 0x0a, 0x5f, 0x59, 0x8f, 0x71, 0xa8, 0x21,
      0x38, 0x07, 0xef, 0xd0, 0x98, 0x5a, 0x8a, 0x7f, 0xef, 0x78, 0xac, 0x31,
      0xae, 0xff, 0xc2, 0x35, 0xad, 0xe7, 0x79, 0x20, 0xbe, 0x23, 0x4b, 0x6a,
      0x65, 0x4d, 0xdf, 0x14, 0x61, 0x16, 0x99, 0x56, 0x1f, 0xf4, 0xed, 0xfb,
      0x6c, 0xff, 0xce, 0x19
    };


       ret |= mbedtls_mpi_read_binary(&ecdsa.Q.X, pub_key, 32);
       ret |= mbedtls_mpi_read_binary(&ecdsa.Q.Y, pub_key + 32, 32);
       ret |= mbedtls_mpi_lset(&ecdsa.Q.Z, 1);
       if (ret != 0)
               goto cleanup;

           mbedtls_mpi r, s;
           mbedtls_mpi_init(&r);
           mbedtls_mpi_init(&s);

           mbedtls_mpi_read_binary(&r, signature, 32);
           mbedtls_mpi_read_binary(&s, signature + 32, 32);

           ret = mbedtls_ecdsa_verify(&ecdsa.grp, hash, sizeof(hash),
                                      &ecdsa.Q, &r, &s);

           mbedtls_mpi_free(&r);
           mbedtls_mpi_free(&s);

       cleanup:
           mbedtls_ecdsa_free(&ecdsa);

           return (ret == 0);
}



static uint32_t GetFlashSector(uint32_t addr)
{

    if (addr >= 0x08000000 && addr < 0x08100000)
    {
        return (addr - 0x08000000) / (128*1024);
    }
    else if (addr >= 0x08100000 && addr < 0x08200000)
    {
        return (addr - 0x08100000) / (128*1024);
    }
    else
    {
        return 0xFFFFFFFF;
    }
}

static uint32_t GetFlashBank(uint32_t addr)
{
    if (addr < 0x08100000)
        return FLASH_BANK_1; // Bank0
    else
        return FLASH_BANK_2; // Bank1
}

static void FlashWriteUserData(uint32_t addr, UserData *user)
{
    HAL_StatusTypeDef status;

    uint32_t sector = GetFlashSector(addr);
    uint32_t bank   = GetFlashBank(addr);

    if (sector == 0xFFFFFFFF)
    {
    	Error_Handler();
    }

    HAL_FLASH_Unlock();

    FLASH_EraseInitTypeDef EraseInitStruct = {0};
    uint32_t SectorError = 0;

    EraseInitStruct.TypeErase    = FLASH_TYPEERASE_SECTORS;
    EraseInitStruct.Banks        = bank;
    EraseInitStruct.Sector       = sector;
    EraseInitStruct.NbSectors    = 1;
    EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;

    status = HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError);
    if (status != HAL_OK) Error_Handler();

    uint32_t *p = (uint32_t*)user;
    uint32_t words = sizeof(UserData) / 4;

    for (uint32_t i = 0; i < words; i++)
    {
        status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_FLASHWORD, addr + i*4, *(p + i));
        if (status != HAL_OK) Error_Handler();
    }
    HAL_FLASH_Lock();
}





/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_MBEDTLS_Init();
  /* USER CODE BEGIN 2 */
  BSP_LED_Init(LED_RED);
  UserData *user = (UserData*)USER_DATA_ADDR;
   uint32_t active_bank_addr = (user->ActiveBankFlag == 0)?APPLICATION_BANK0_ADDR:APPLICATION_BANK1_ADDR;
   uint32_t inactive_bank_addr = (user->ActiveBankFlag == 0)?APPLICATION_BANK1_ADDR:APPLICATION_BANK0_ADDR;

   uint8_t *active_signature = (user->ActiveBankFlag == 0)?user->SignatureBank0:user->SignatureBank1;
   uint8_t *inactive_signature = (user->ActiveBankFlag == 0)?user->SignatureBank1:user->SignatureBank0;
   if(user->UpdateReadyFlag)
   {
 	  if(ValidateFirmware(inactive_bank_addr, inactive_signature))
 	  {
 		 user->ActiveBankFlag = (user->ActiveBankFlag == 0)?1:0;
 		 user->UpdateReadyFlag = 0;
 		 active_bank_addr = (user->ActiveBankFlag == 0)?APPLICATION_BANK0_ADDR:APPLICATION_BANK1_ADDR;
 		 active_signature = (user->ActiveBankFlag == 0)?user->SignatureBank0:user->SignatureBank1;
 		 inactive_bank_addr = (user->ActiveBankFlag == 0)?APPLICATION_BANK1_ADDR:APPLICATION_BANK0_ADDR;
 		 inactive_signature = (user->ActiveBankFlag == 0)?user->SignatureBank1:user->SignatureBank0;
 	  }
 	  else
 	  {
 		 user->UpdateReadyFlag = 0;
 	  }
 	 FlashWriteUserData(USER_DATA_ADDR, user);
   }

   if(!ValidateFirmware(active_bank_addr, active_signature))
   {
	   // Rollback
	   user->ActiveBankFlag = (user->ActiveBankFlag == 0)?1:0;
	   active_bank_addr = (user->ActiveBankFlag == 0)?APPLICATION_BANK0_ADDR:APPLICATION_BANK1_ADDR;
	   active_signature = (user->ActiveBankFlag == 0)?user->SignatureBank0:user->SignatureBank1;
	   if(ValidateFirmware(active_bank_addr, active_signature))
	   {
		   FlashWriteUserData(USER_DATA_ADDR, user);
	   }
	   else
	   {

		   Error_Handler();
	   }

   }
   JumpToApplication(active_bank_addr);
  /* USER CODE END 2 */

  /* Initialize leds */
  BSP_LED_Init(LED_GREEN);
  BSP_LED_Init(LED_YELLOW);
  BSP_LED_Init(LED_RED);

  /* Initialize USER push-button, will be used to trigger an interrupt each time it's pressed.*/
  BSP_PB_Init(BUTTON_USER, BUTTON_MODE_EXTI);

  /* Initialize COM1 port (115200, 8 bits (7-bit data + 1 stop bit), no parity */
  BspCOMInit.BaudRate   = 115200;
  BspCOMInit.WordLength = COM_WORDLENGTH_8B;
  BspCOMInit.StopBits   = COM_STOPBITS_1;
  BspCOMInit.Parity     = COM_PARITY_NONE;
  BspCOMInit.HwFlowCtl  = COM_HWCONTROL_NONE;
  if (BSP_COM_Init(COM1, &BspCOMInit) != BSP_ERROR_NONE)
  {
    Error_Handler();
  }

  /* USER CODE BEGIN BSP */

  /* -- Sample board code to send message over COM1 port ---- */
  printf("Welcome to STM32 world !\n\r");

  /* -- Sample board code to switch on leds ---- */
  BSP_LED_On(LED_GREEN);
  BSP_LED_On(LED_YELLOW);
  BSP_LED_On(LED_RED);

  /* USER CODE END BSP */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {

    /* -- Sample board code for User push-button in interrupt mode ---- */
    if (BspButtonState == BUTTON_PRESSED)
    {
      /* Update button state */
      BspButtonState = BUTTON_RELEASED;
      /* -- Sample board code to toggle leds ---- */
      BSP_LED_Toggle(LED_GREEN);
      BSP_LED_Toggle(LED_YELLOW);
      BSP_LED_Toggle(LED_RED);

      /* ..... Perform your action ..... */
    }
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Supply configuration update enable
  */
  HAL_PWREx_ConfigSupply(PWR_LDO_SUPPLY);

  /** Configure the main internal regulator output voltage
  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE0);

  while(!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {}

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_DIV1;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 32;
  RCC_OscInitStruct.PLL.PLLN = 480;
  RCC_OscInitStruct.PLL.PLLP = 2;
  RCC_OscInitStruct.PLL.PLLQ = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1VCIRANGE_1;
  RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1VCOWIDE;
  RCC_OscInitStruct.PLL.PLLFRACN = 0;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                              |RCC_CLOCKTYPE_D3PCLK1|RCC_CLOCKTYPE_D1PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.SYSCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_APB3_DIV2;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_APB1_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_APB2_DIV2;
  RCC_ClkInitStruct.APB4CLKDivider = RCC_APB4_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

 /* MPU Configuration */

void MPU_Config(void)
{
  MPU_Region_InitTypeDef MPU_InitStruct = {0};

  /* Disables the MPU */
  HAL_MPU_Disable();

  /** Initializes and configures the Region and the memory to be protected
  */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = 0x0;
  MPU_InitStruct.Size = MPU_REGION_SIZE_4GB;
  MPU_InitStruct.SubRegionDisable = 0x87;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL0;
  MPU_InitStruct.AccessPermission = MPU_REGION_NO_ACCESS;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
  MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  /* Enables the MPU */
  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);

}

/**
  * @brief BSP Push Button callback
  * @param Button Specifies the pressed button
  * @retval None
  */
void BSP_PB_Callback(Button_TypeDef Button)
{
  if (Button == BUTTON_USER)
  {
    BspButtonState = BUTTON_PRESSED;
  }
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  BSP_LED_On(LED_RED);
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
