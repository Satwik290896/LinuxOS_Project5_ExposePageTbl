/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Device Tree defines for Lochnagar pinctrl
 *
 * Copyright (c) 2018 Cirrus Logic, Inc. and
 *                    Cirrus Logic International Semiconductor Ltd.
 *
 * Author: Charles Keepax <ckeepax@opensource.cirrus.com>
 */

#ifndef DT_BINDINGS_PINCTRL_LOCHNAGAR_H
#define DT_BINDINGS_PINCTRL_LOCHNAGAR_H

#define LOCHNAGAR1_PIN_CDC_RESET		0
#define LOCHNAGAR1_PIN_DSP_RESET		1
#define LOCHNAGAR1_PIN_CDC_CIF1MODE		2
#define LOCHNAGAR1_PIN_NUM_GPIOS		3

#define LOCHNAGAR2_PIN_CDC_RESET		0
#define LOCHNAGAR2_PIN_DSP_RESET		1
#define LOCHNAGAR2_PIN_CDC_CIF1MODE		2
#define LOCHNAGAR2_PIN_CDC_LDOENA		3
#define LOCHNAGAR2_PIN_SPDIF_HWMODE		4
#define LOCHNAGAR2_PIN_SPDIF_RESET		5
#define LOCHNAGAR2_PIN_FPGA_GPIO1		6
#define LOCHNAGAR2_PIN_FPGA_GPIO2		7
#define LOCHNAGAR2_PIN_FPGA_GPIO3		8
#define LOCHNAGAR2_PIN_FPGA_GPIO4		9
#define LOCHNAGAR2_PIN_FPGA_GPIO5		10
#define LOCHNAGAR2_PIN_FPGA_GPIO6		11
#define LOCHNAGAR2_PIN_CDC_GPIO1		12
#define LOCHNAGAR2_PIN_CDC_GPIO2		13
#define LOCHNAGAR2_PIN_CDC_GPIO3		14
#define LOCHNAGAR2_PIN_CDC_GPIO4		15
#define LOCHNAGAR2_PIN_CDC_GPIO5		16
#define LOCHNAGAR2_PIN_CDC_GPIO6		17
#define LOCHNAGAR2_PIN_CDC_GPIO7		18
#define LOCHNAGAR2_PIN_CDC_GPIO8		19
#define LOCHNAGAR2_PIN_DSP_GPIO1		20
#define LOCHNAGAR2_PIN_DSP_GPIO2		21
#define LOCHNAGAR2_PIN_DSP_GPIO3		22
#define LOCHNAGAR2_PIN_DSP_GPIO4		23
#define LOCHNAGAR2_PIN_DSP_GPIO5		24
#define LOCHNAGAR2_PIN_DSP_GPIO6		25
#define LOCHNAGAR2_PIN_GF_GPIO2			26
#define LOCHNAGAR2_PIN_GF_GPIO3			27
#define LOCHNAGAR2_PIN_GF_GPIO7			28
#define LOCHNAGAR2_PIN_CDC_AIF1_BCLK		29
#define LOCHNAGAR2_PIN_CDC_AIF1_RXDAT		30
#define LOCHNAGAR2_PIN_CDC_AIF1_LRCLK		31
#define LOCHNAGAR2_PIN_CDC_AIF1_TXDAT		32
#define LOCHNAGAR2_PIN_CDC_AIF2_BCLK		33
#define LOCHNAGAR2_PIN_CDC_AIF2_RXDAT		34
#define LOCHNAGAR2_PIN_CDC_AIF2_LRCLK		35
#define LOCHNAGAR2_PIN_CDC_AIF2_TXDAT		36
#define LOCHNAGAR2_PIN_CDC_AIF3_BCLK		37
#define LOCHNAGAR2_PIN_CDC_AIF3_RXDAT		38
#define LOCHNAGAR2_PIN_CDC_AIF3_LRCLK		39
#define LOCHNAGAR2_PIN_CDC_AIF3_TXDAT		40
#define LOCHNAGAR2_PIN_DSP_AIF1_BCLK		41
#define LOCHNAGAR2_PIN_DSP_AIF1_RXDAT		42
#define LOCHNAGAR2_PIN_DSP_AIF1_LRCLK		43
#define LOCHNAGAR2_PIN_DSP_AIF1_TXDAT		44
#define LOCHNAGAR2_PIN_DSP_AIF2_BCLK		45
#define LOCHNAGAR2_PIN_DSP_AIF2_RXDAT		46
#define LOCHNAGAR2_PIN_DSP_AIF2_LRCLK		47
#define LOCHNAGAR2_PIN_DSP_AIF2_TXDAT		48
#define LOCHNAGAR2_PIN_PSIA1_BCLK		49
#define LOCHNAGAR2_PIN_PSIA1_RXDAT		50
#define LOCHNAGAR2_PIN_PSIA1_LRCLK		51
#define LOCHNAGAR2_PIN_PSIA1_TXDAT		52
#define LOCHNAGAR2_PIN_PSIA2_BCLK		53
#define LOCHNAGAR2_PIN_PSIA2_RXDAT		54
#define LOCHNAGAR2_PIN_PSIA2_LRCLK		55
#define LOCHNAGAR2_PIN_PSIA2_TXDAT		56
#define LOCHNAGAR2_PIN_GF_AIF3_BCLK		57
#define LOCHNAGAR2_PIN_GF_AIF3_RXDAT		58
#define LOCHNAGAR2_PIN_GF_AIF3_LRCLK		59
#define LOCHNAGAR2_PIN_GF_AIF3_TXDAT		60
#define LOCHNAGAR2_PIN_GF_AIF4_BCLK		61
#define LOCHNAGAR2_PIN_GF_AIF4_RXDAT		62
#define LOCHNAGAR2_PIN_GF_AIF4_LRCLK		63
#define LOCHNAGAR2_PIN_GF_AIF4_TXDAT		64
#define LOCHNAGAR2_PIN_GF_AIF1_BCLK		65
#define LOCHNAGAR2_PIN_GF_AIF1_RXDAT		66
#define LOCHNAGAR2_PIN_GF_AIF1_LRCLK		67
#define LOCHNAGAR2_PIN_GF_AIF1_TXDAT		68
#define LOCHNAGAR2_PIN_GF_AIF2_BCLK		69
#define LOCHNAGAR2_PIN_GF_AIF2_RXDAT		70
#define LOCHNAGAR2_PIN_GF_AIF2_LRCLK		71
#define LOCHNAGAR2_PIN_GF_AIF2_TXDAT		72
#define LOCHNAGAR2_PIN_DSP_UART1_RX		73
#define LOCHNAGAR2_PIN_DSP_UART1_TX		74
#define LOCHNAGAR2_PIN_DSP_UART2_RX		75
#define LOCHNAGAR2_PIN_DSP_UART2_TX		76
#define LOCHNAGAR2_PIN_GF_UART2_RX		77
#define LOCHNAGAR2_PIN_GF_UART2_TX		78
#define LOCHNAGAR2_PIN_USB_UART_RX		79
#define LOCHNAGAR2_PIN_CDC_PDMCLK1		80
#define LOCHNAGAR2_PIN_CDC_PDMDAT1		81
#define LOCHNAGAR2_PIN_CDC_PDMCLK2		82
#define LOCHNAGAR2_PIN_CDC_PDMDAT2		83
#define LOCHNAGAR2_PIN_CDC_DMICCLK1		84
#define LOCHNAGAR2_PIN_CDC_DMICDAT1		85
#define LOCHNAGAR2_PIN_CDC_DMICCLK2		86
#define LOCHNAGAR2_PIN_CDC_DMICDAT2		87
#define LOCHNAGAR2_PIN_CDC_DMICCLK3		88
#define LOCHNAGAR2_PIN_CDC_DMICDAT3		89
#define LOCHNAGAR2_PIN_CDC_DMICCLK4		90
#define LOCHNAGAR2_PIN_CDC_DMICDAT4		91
#define LOCHNAGAR2_PIN_DSP_DMICCLK1		92
#define LOCHNAGAR2_PIN_DSP_DMICDAT1		93
#define LOCHNAGAR2_PIN_DSP_DMICCLK2		94
#define LOCHNAGAR2_PIN_DSP_DMICDAT2		95
#define LOCHNAGAR2_PIN_I2C2_SCL			96
#define LOCHNAGAR2_PIN_I2C2_SDA			97
#define LOCHNAGAR2_PIN_I2C3_SCL			98
#define LOCHNAGAR2_PIN_I2C3_SDA			99
#define LOCHNAGAR2_PIN_I2C4_SCL			100
#define LOCHNAGAR2_PIN_I2C4_SDA			101
#define LOCHNAGAR2_PIN_DSP_STANDBY		102
#define LOCHNAGAR2_PIN_CDC_MCLK1		103
#define LOCHNAGAR2_PIN_CDC_MCLK2		104
#define LOCHNAGAR2_PIN_DSP_CLKIN		105
#define LOCHNAGAR2_PIN_PSIA1_MCLK		106
#define LOCHNAGAR2_PIN_PSIA2_MCLK		107
#define LOCHNAGAR2_PIN_GF_GPIO1			108
#define LOCHNAGAR2_PIN_GF_GPIO5			109
#define LOCHNAGAR2_PIN_DSP_GPIO20		110
#define LOCHNAGAR2_PIN_NUM_GPIOS		111

#endif
