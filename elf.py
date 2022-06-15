#!/usr/bin/env python3

import argparse
import demjson3
import io
import json
import os
import struct

# The ELF file header.  This appears at the start of every ELF file.

EI_NIDENT = 16

EI_MAG0 = 0  # File identification byte 0 index
ELFMAG0 = 0x7F  # Magic number byte 0

EI_MAG1 = 1  # File identification byte 1 index
ELFMAG1 = "E"  # Magic number byte 1

EI_MAG2 = 2  # File identification byte 2 index
ELFMAG2 = "L"  # Magic number byte 2

EI_MAG3 = 3  # File identification byte 3 index
ELFMAG3 = "F"  # Magic number byte 3

# Conglomeration of the identification bytes, for easy testing as a word.
ELFMAG = b"\x7fELF"
SELFMAG = 4

Elf_Ident = [
    ("ELF_MAG",       ("char", SELFMAG)),
    ("EI_CLASS",      ("uint8", 1)),
    ("EI_DATA",       ("uint8", 1)),
    ("EI_VERSION",    ("uint8", 1)),
    ("EI_OSABI",      ("uint8", 1)),
    ("EI_ABIVERSION", ("uint8", 1)),
    ("EI_PAD",        ("char",  7)),
]

Elf32_Ehdr = [
    ("e_ident",     ("Elf_Ident",  1)),  # Magic number and other info 
    ("e_type",      ("Elf32_Half", 1)),  # Object file type 
    ("e_machine",   ("Elf32_Half", 1)),  # Architecture 
    ("e_version",   ("Elf32_Word", 1)),  # Object file version 
    ("e_entry",     ("Elf32_Addr", 1)),  # Entry point virtual address 
    ("e_phoff",     ("Elf32_Off",  1)),  # Program header table file offset 
    ("e_shoff",     ("Elf32_Off",  1)),  # Section header table file offset 
    ("e_flags",     ("Elf32_Word", 1)),  # Processor-specific flags 
    ("e_ehsize",    ("Elf32_Half", 1)),  # ELF header size in bytes 
    ("e_phentsize", ("Elf32_Half", 1)),  # Program header table entry size 
    ("e_phnum",     ("Elf32_Half", 1)),  # Program header table entry count 
    ("e_shentsize", ("Elf32_Half", 1)),  # Section header table entry size 
    ("e_shnum",     ("Elf32_Half", 1)),  # Section header table entry count 
    ("e_shstrndx",  ("Elf32_Half", 1))   # Section header string table index 
]

Elf64_Ehdr = [
    ("e_ident",     ("Elf_Ident",  1)),  # Magic number and other info 
    ("e_type",      ("Elf64_Half", 1)),  # Object file type 
    ("e_machine",   ("Elf64_Half", 1)),  # Architecture 
    ("e_version",   ("Elf64_Word", 1)),  # Object file version 
    ("e_entry",     ("Elf64_Addr", 1)),  # Entry point virtual address 
    ("e_phoff",     ("Elf64_Off",  1)),  # Program header table file offset 
    ("e_shoff",     ("Elf64_Off",  1)),  # Section header table file offset 
    ("e_flags",     ("Elf64_Word", 1)),  # Processor-specific flags 
    ("e_ehsize",    ("Elf64_Half", 1)),  # ELF header size in bytes 
    ("e_phentsize", ("Elf64_Half", 1)),  # Program header table entry size 
    ("e_phnum",     ("Elf64_Half", 1)),  # Program header table entry count 
    ("e_shentsize", ("Elf64_Half", 1)),  # Section header table entry size 
    ("e_shnum",     ("Elf64_Half", 1)),  # Section header table entry count 
    ("e_shstrndx",  ("Elf64_Half", 1))   # Section header string table index 
]

EI_CLASS = 4  # File class byte index
ELFCLASSNONE = 0  # Invalid class
ELFCLASS32 = 1  # 32-bit objects
ELFCLASS64 = 2  # 64-bit objects
ELFCLASSNUM = 3

EI_DATA = 5  # Data encoding byte index
ELFDATANONE = 0  # Invalid data encoding
ELFDATA2LSB = 1  # 2's complement, little endian
ELFDATA2MSB = 2  # 2's complement, big endian
ELFDATANUM = 3

EI_VERSION = 6  # File version byte index
# Value must be EV_CURRENT

EI_OSABI = 7  # OS ABI identification
ELFOSABI_NONE = 0  # UNIX System V ABI
ELFOSABI_SYSV = 0  # Alias.
ELFOSABI_HPUX = 1  # HP-UX
ELFOSABI_NETBSD = 2  # NetBSD.
ELFOSABI_GNU = 3  # Object uses GNU ELF extensions.
ELFOSABI_LINUX = ELFOSABI_GNU  # Compatibility alias.
ELFOSABI_SOLARIS = 6  # Sun Solaris.
ELFOSABI_AIX = 7  # IBM AIX.
ELFOSABI_IRIX = 8  # SGI Irix.
ELFOSABI_FREEBSD = 9  # FreeBSD.
ELFOSABI_TRU64 = 10  # Compaq TRU64 UNIX.
ELFOSABI_MODESTO = 11  # Novell Modesto.
ELFOSABI_OPENBSD = 12  # OpenBSD.
ELFOSABI_ARM_AEABI = 64  # ARM EABI
ELFOSABI_ARM = 97  # ARM
ELFOSABI_STANDALONE = 255  # Standalone (embedded) application

EI_ABIVERSION = 8  # ABI version

EI_PAD = 9  # Byte index of padding bytes

# Legal values for e_type (object file type).

ET_NONE = 0  # No file type
ET_REL = 1  # Relocatable file
ET_EXEC = 2  # Executable file
ET_DYN = 3  # Shared object file
ET_CORE = 4  # Core file
ET_NUM = 5  # Number of defined types
ET_LOOS = 0xFE00  # OS-specific range start
ET_HIOS = 0xFEFF  # OS-specific range end
ET_LOPROC = 0xFF00  # Processor-specific range start
ET_HIPROC = 0xFFFF  # Processor-specific range end

# Legal values for e_machine (architecture).

EM_NONE = 0  # No machine
EM_M32 = 1  # AT&T WE 32100
EM_SPARC = 2  # SUN SPARC
EM_386 = 3  # Intel 80386
EM_68K = 4  # Motorola m68k family
EM_88K = 5  # Motorola m88k family
EM_IAMCU = 6  # Intel MCU
EM_860 = 7  # Intel 80860
EM_MIPS = 8  # MIPS R3000 big-endian
EM_S370 = 9  # IBM System/370
EM_MIPS_RS3_LE = 10  # MIPS R3000 little-endian
# reserved 11-14
EM_PARISC = 15  # HPPA
# reserved 16
EM_VPP500 = 17  # Fujitsu VPP500
EM_SPARC32PLUS = 18  # Sun's "v8plus"
EM_960 = 19  # Intel 80960
EM_PPC = 20  # PowerPC
EM_PPC64 = 21  # PowerPC 64-bit
EM_S390 = 22  # IBM S390
EM_SPU = 23  # IBM SPU/SPC
# reserved 24-35
EM_V800 = 36  # NEC V800 series
EM_FR20 = 37  # Fujitsu FR20
EM_RH32 = 38  # TRW RH-32
EM_RCE = 39  # Motorola RCE
EM_ARM = 40  # ARM
EM_FAKE_ALPHA = 41  # Digital Alpha
EM_SH = 42  # Hitachi SH
EM_SPARCV9 = 43  # SPARC v9 64-bit
EM_TRICORE = 44  # Siemens Tricore
EM_ARC = 45  # Argonaut RISC Core
EM_H8_300 = 46  # Hitachi H8/300
EM_H8_300H = 47  # Hitachi H8/300H
EM_H8S = 48  # Hitachi H8S
EM_H8_500 = 49  # Hitachi H8/500
EM_IA_64 = 50  # Intel Merced
EM_MIPS_X = 51  # Stanford MIPS-X
EM_COLDFIRE = 52  # Motorola Coldfire
EM_68HC12 = 53  # Motorola M68HC12
EM_MMA = 54  # Fujitsu MMA Multimedia Accelerator
EM_PCP = 55  # Siemens PCP
EM_NCPU = 56  # Sony nCPU embeeded RISC
EM_NDR1 = 57  # Denso NDR1 microprocessor
EM_STARCORE = 58  # Motorola Start*Core processor
EM_ME16 = 59  # Toyota ME16 processor
EM_ST100 = 60  # STMicroelectronic ST100 processor
EM_TINYJ = 61  # Advanced Logic Corp. Tinyj emb.fam
EM_X86_64 = 62  # AMD x86-64 architecture
EM_PDSP = 63  # Sony DSP Processor
EM_PDP10 = 64  # Digital PDP-10
EM_PDP11 = 65  # Digital PDP-11
EM_FX66 = 66  # Siemens FX66 microcontroller
EM_ST9PLUS = 67  # STMicroelectronics ST9+ 8/16 mc
EM_ST7 = 68  # STmicroelectronics ST7 8 bit mc
EM_68HC16 = 69  # Motorola MC68HC16 microcontroller
EM_68HC11 = 70  # Motorola MC68HC11 microcontroller
EM_68HC08 = 71  # Motorola MC68HC08 microcontroller
EM_68HC05 = 72  # Motorola MC68HC05 microcontroller
EM_SVX = 73  # Silicon Graphics SVx
EM_ST19 = 74  # STMicroelectronics ST19 8 bit mc
EM_VAX = 75  # Digital VAX
EM_CRIS = 76  # Axis Communications 32-bit emb.proc
EM_JAVELIN = 77  # Infineon Technologies 32-bit emb.proc
EM_FIREPATH = 78  # Element 14 64-bit DSP Processor
EM_ZSP = 79  # LSI Logic 16-bit DSP Processor
EM_MMIX = 80  # Donald Knuth's educational 64-bit proc
EM_HUANY = 81  # Harvard University machine-independent object files
EM_PRISM = 82  # SiTera Prism
EM_AVR = 83  # Atmel AVR 8-bit microcontroller
EM_FR30 = 84  # Fujitsu FR30
EM_D10V = 85  # Mitsubishi D10V
EM_D30V = 86  # Mitsubishi D30V
EM_V850 = 87  # NEC v850
EM_M32R = 88  # Mitsubishi M32R
EM_MN10300 = 89  # Matsushita MN10300
EM_MN10200 = 90  # Matsushita MN10200
EM_PJ = 91  # picoJava
EM_OPENRISC = 92  # OpenRISC 32-bit embedded processor
EM_ARC_COMPACT = 93  # ARC International ARCompact
EM_XTENSA = 94  # Tensilica Xtensa Architecture
EM_VIDEOCORE = 95  # Alphamosaic VideoCore
EM_TMM_GPP = 96  # Thompson Multimedia General Purpose Proc
EM_NS32K = 97  # National Semi. 32000
EM_TPC = 98  # Tenor Network TPC
EM_SNP1K = 99  # Trebia SNP 1000
EM_ST200 = 100  # STMicroelectronics ST200
EM_IP2K = 101  # Ubicom IP2xxx
EM_MAX = 102  # MAX processor
EM_CR = 103  # National Semi. CompactRISC
EM_F2MC16 = 104  # Fujitsu F2MC16
EM_MSP430 = 105  # Texas Instruments msp430
EM_BLACKFIN = 106  # Analog Devices Blackfin DSP
EM_SE_C33 = 107  # Seiko Epson S1C33 family
EM_SEP = 108  # Sharp embedded microprocessor
EM_ARCA = 109  # Arca RISC
EM_UNICORE = 110  # PKU-Unity & MPRC Peking Uni. mc series
EM_EXCESS = 111  # eXcess configurable cpu
EM_DXP = 112  # Icera Semi. Deep Execution Processor
EM_ALTERA_NIOS2 = 113  # Altera Nios II
EM_CRX = 114  # National Semi. CompactRISC CRX
EM_XGATE = 115  # Motorola XGATE
EM_C166 = 116  # Infineon C16x/XC16x
EM_M16C = 117  # Renesas M16C
EM_DSPIC30F = 118  # Microchip Technology dsPIC30F
EM_CE = 119  # Freescale Communication Engine RISC
EM_M32C = 120  # Renesas M32C
# reserved 121-130
EM_TSK3000 = 131  # Altium TSK3000
EM_RS08 = 132  # Freescale RS08
EM_SHARC = 133  # Analog Devices SHARC family
EM_ECOG2 = 134  # Cyan Technology eCOG2
EM_SCORE7 = 135  # Sunplus S+core7 RISC
EM_DSP24 = 136  # New Japan Radio (NJR) 24-bit DSP
EM_VIDEOCORE3 = 137  # Broadcom VideoCore III
EM_LATTICEMICO32 = 138  # RISC for Lattice FPGA
EM_SE_C17 = 139  # Seiko Epson C17
EM_TI_C6000 = 140  # Texas Instruments TMS320C6000 DSP
EM_TI_C2000 = 141  # Texas Instruments TMS320C2000 DSP
EM_TI_C5500 = 142  # Texas Instruments TMS320C55x DSP
EM_TI_ARP32 = 143  # Texas Instruments App. Specific RISC
EM_TI_PRU = 144  # Texas Instruments Prog. Realtime Unit
# reserved 145-159
EM_MMDSP_PLUS = 160  # STMicroelectronics 64bit VLIW DSP
EM_CYPRESS_M8C = 161  # Cypress M8C
EM_R32C = 162  # Renesas R32C
EM_TRIMEDIA = 163  # NXP Semi. TriMedia
EM_QDSP6 = 164  # QUALCOMM DSP6
EM_8051 = 165  # Intel 8051 and variants
EM_STXP7X = 166  # STMicroelectronics STxP7x
EM_NDS32 = 167  # Andes Tech. compact code emb. RISC
EM_ECOG1X = 168  # Cyan Technology eCOG1X
EM_MAXQ30 = 169  # Dallas Semi. MAXQ30 mc
EM_XIMO16 = 170  # New Japan Radio (NJR) 16-bit DSP
EM_MANIK = 171  # M2000 Reconfigurable RISC
EM_CRAYNV2 = 172  # Cray NV2 vector architecture
EM_RX = 173  # Renesas RX
EM_METAG = 174  # Imagination Tech. META
EM_MCST_ELBRUS = 175  # MCST Elbrus
EM_ECOG16 = 176  # Cyan Technology eCOG16
EM_CR16 = 177  # National Semi. CompactRISC CR16
EM_ETPU = 178  # Freescale Extended Time Processing Unit
EM_SLE9X = 179  # Infineon Tech. SLE9X
EM_L10M = 180  # Intel L10M
EM_K10M = 181  # Intel K10M
# reserved 182
EM_AARCH64 = 183  # ARM AARCH64
# reserved 184
EM_AVR32 = 185  # Amtel 32-bit microprocessor
EM_STM8 = 186  # STMicroelectronics STM8
EM_TILE64 = 187  # Tileta TILE64
EM_TILEPRO = 188  # Tilera TILEPro
EM_MICROBLAZE = 189  # Xilinx MicroBlaze
EM_CUDA = 190  # NVIDIA CUDA
EM_TILEGX = 191  # Tilera TILE-Gx
EM_CLOUDSHIELD = 192  # CloudShield
EM_COREA_1ST = 193  # KIPO-KAIST Core-A 1st gen.
EM_COREA_2ND = 194  # KIPO-KAIST Core-A 2nd gen.
EM_ARC_COMPACT2 = 195  # Synopsys ARCompact V2
EM_OPEN8 = 196  # Open8 RISC
EM_RL78 = 197  # Renesas RL78
EM_VIDEOCORE5 = 198  # Broadcom VideoCore V
EM_78KOR = 199  # Renesas 78KOR
EM_56800EX = 200  # Freescale 56800EX DSC
EM_BA1 = 201  # Beyond BA1
EM_BA2 = 202  # Beyond BA2
EM_XCORE = 203  # XMOS xCORE
EM_MCHP_PIC = 204  # Microchip 8-bit PIC(r)
# reserved 205-209
EM_KM32 = 210  # KM211 KM32
EM_KMX32 = 211  # KM211 KMX32
EM_EMX16 = 212  # KM211 KMX16
EM_EMX8 = 213  # KM211 KMX8
EM_KVARC = 214  # KM211 KVARC
EM_CDP = 215  # Paneve CDP
EM_COGE = 216  # Cognitive Smart Memory Processor
EM_COOL = 217  # Bluechip CoolEngine
EM_NORC = 218  # Nanoradio Optimized RISC
EM_CSR_KALIMBA = 219  # CSR Kalimba
EM_Z80 = 220  # Zilog Z80
EM_VISIUM = 221  # Controls and Data Services VISIUMcore
EM_FT32 = 222  # FTDI Chip FT32
EM_MOXIE = 223  # Moxie processor
EM_AMDGPU = 224  # AMD GPU
# reserved 225-242
EM_RISCV = 243  # RISC-V

EM_BPF = 247  # Linux BPF -- in-kernel virtual machine

EM_NUM = 248

# Old spellings/synonyms.

EM_ARC_A5 = EM_ARC_COMPACT

# If it is necessary to assign new unofficial EM_* values, please
#   pick large random numbers (0x8523, 0xa7f2, etc.) to minimize the
#   chances of collision with official or non-GNU unofficial values.

EM_ALPHA = 0x9026

# Legal values for e_version (version).

EV_NONE = 0  # Invalid ELF version
EV_CURRENT = 1  # Current version
EV_NUM = 2

# Program segment header

Elf32_Phdr = [
  ("p_type",	   ("Elf32_Word",  1)),  # Segment type
  ("p_offset",	   ("Elf32_Off",   1)),  # Segment file offset
  ("p_vaddr",	   ("Elf32_Addr",  1)),  # Segment virtual address
  ("p_paddr",	   ("Elf32_Addr",  1)),  # Segment physical address 
  ("p_filesz",	   ("Elf32_Word",  1)),  # Segment size in file 
  ("p_memsz",	   ("Elf32_Word",  1)),  # Segment size in memory 
  ("p_flags",	   ("Elf32_Word",  1)),  # Segment flags 
  ("p_align",	   ("Elf32_Word",  1))   # Segment alignment 
]                  
				   
Elf64_Phdr = [     
  ("p_type",       ("Elf64_Word",  1)),  # Segment type 
  ("p_flags",      ("Elf64_Word",  1)),  # Segment flags 
  ("p_offset",     ("Elf64_Off",   1)),  # Segment file offset 
  ("p_vaddr",      ("Elf64_Addr",  1)),  # Segment virtual address 
  ("p_paddr",      ("Elf64_Addr",  1)),  # Segment physical address 
  ("p_filesz",     ("Elf64_Xword", 1)),  # Segment size in file 
  ("p_memsz",      ("Elf64_Xword", 1)),  # Segment size in memory 
  ("p_align",      ("Elf64_Xword", 1))   # Segment alignment 
]

# Section header.

Elf32_Shdr = [
  ("sh_name",      ("Elf32_Word",  1)),  # Section name (string tbl index) 
  ("sh_type",      ("Elf32_Word",  1)),  # Section type 
  ("sh_flags",     ("Elf32_Word",  1)),  # Section flags 
  ("sh_addr",      ("Elf32_Addr",  1)),  # Section virtual addr at execution 
  ("sh_offset",    ("Elf32_Off" ,  1)),  # Section file offset 
  ("sh_size",      ("Elf32_Word",  1)),  # Section size in bytes 
  ("sh_link",      ("Elf32_Word",  1)),  # Link to another section 
  ("sh_info",      ("Elf32_Word",  1)),  # Additional section information 
  ("sh_addralign", ("Elf32_Word",  1)),  # Section alignment 
  ("sh_entsize",   ("Elf32_Word",  1))   # Entry size if section holds table 
]                                  
   
Elf64_Shdr = [                     
  ("sh_name",      ("Elf64_Word",  1)),  # Section name (string tbl index) 
  ("sh_type",      ("Elf64_Word",  1)),  # Section type 
  ("sh_flags",     ("Elf64_Xword", 1)),  # Section flags 
  ("sh_addr",      ("Elf64_Addr",  1)),  # Section virtual addr at execution 
  ("sh_offset",    ("Elf64_Off" ,  1)),  # Section file offset 
  ("sh_size",      ("Elf64_Xword", 1)),  # Section size in bytes 
  ("sh_link",      ("Elf64_Word",  1)),  # Link to another section 
  ("sh_info",      ("Elf64_Word",  1)),  # Additional section information 
  ("sh_addralign", ("Elf64_Xword", 1)),  # Section alignment 
  ("sh_entsize",   ("Elf64_Xword", 1))   # Entry size if section holds table 
]

class BinaryMarshaller:
	# Map well-known type names into struct format characters.
	def __init__(self, file):
		self.typeNames = {
			'int8'         :'b',
			'uint8'        :'B',
			'int16'        :'h',
			'uint16'       :'H',
			'int32'        :'i',
			'uint32'       :'I',
			'int64'        :'q',
			'uint64'       :'Q',
			'float'        :'f',
			'double'       :'d',
			'char'         :'s',
			'Elf32_Half'   :'H',
			'Elf32_Word'   :'I',
			'Elf32_Off'    :'I',
			'Elf32_Addr'   :'I',
			'Elf64_Half'   :'H',
			'Elf64_Word'   :'I',
			'Elf64_Off'    :'Q',
			'Elf64_Addr'   :'Q',
			'Elf64_Xword'  :'Q'
		}
		self.schemes = ["Elf_Ident", "Elf32_Ehdr", "Elf64_Ehdr"]
		self.file = file
		
	def __enter__(self):
		return self

	def seek(self, offset, from_what = None):
		if not from_what:
			self.file.seek(offset)
		else:
			self.file.seek(offset, from_what)
		
	def tell(self):
		return self.file.tell()	
	
	def read(self, typeName, count = 1, endian = ELFDATA2LSB):
		if typeName in self.schemes:
			return self.readStruct(globals()[typeName], endian)

		if endian == ELFDATA2LSB:
			endian = "<"
		else:
			endian = ">"

		typeFormat = self.typeNames[typeName]
		typeSize = count * struct.calcsize(typeFormat)
		value = self.file.read(typeSize)
		if typeSize != len(value):
			raise RuntimeError("Not enough bytes in file to satisfy read request")
		return struct.unpack(f"{endian}{count}{typeFormat}", value)[0]

	def write(self, obj, typeName, count, endian = ELFDATA2LSB):
		if typeName in self.schemes:
			self.writeStruct(obj, globals()[typeName], endian)
			return

		if endian == ELFDATA2LSB:
			endian = "<"
		else:
			endian = ">"

		typeFormat = self.typeNames[typeName]
		typeSize = count * struct.calcsize(typeFormat)
		obj_packed = struct.pack(f"{endian}{count}{typeFormat}", obj)	
		self.file.write(obj_packed)
		
	def readBytes(self, numBytes):
		return self.file.read(numBytes)
		
	def readCString(self, iLen = 1):
		res = []
		while True:
			c = self.file.read(1)
			if c == "\x00":
				return "".join(res)
			res.append(c)

	def readStruct(self, scheme, endian = ELFDATA2LSB):
		res = dict()
		for name, (typename, count) in scheme:
			res[name] = self.read(typename, count, endian)

		return res

	def writeStruct(self, struct, scheme, endian = ELFDATA2LSB):
		for name, (typename, count) in scheme:
			self.write(struct[name], typename, count, endian)

	def __exit__(self, exc_type, exc_value, traceback):
		if exc_type is not None:
			raise
		return self

class ELF:
	def __init__(self, input_file):
		self.file = io.BytesIO(open(input_file, "rb").read())
		self._parse()

	def _parse(self):
		with BinaryMarshaller(self.file) as bm:
			self.e_ident = bm.readStruct(Elf_Ident, endian = ELFDATA2MSB)
			assert(self.e_ident["ELF_MAG"] == ELFMAG)
			assert(self.e_ident["EI_VERSION"] == EV_CURRENT)
			endian = self.e_ident["EI_DATA"]

			bm.seek(0)
			if self.e_ident["EI_CLASS"] == ELFCLASS32:
				Elf_Phdr = Elf32_Phdr
				Elf_Shdr = Elf32_Shdr
				self.ehdr = bm.readStruct(Elf32_Ehdr, endian = endian)
			elif self.e_ident["EI_CLASS"] == ELFCLASS64:
				Elf_Phdr = Elf64_Phdr
				Elf_Shdr = Elf64_Shdr
				self.ehdr = bm.readStruct(Elf64_Ehdr, endian = endian)
			else:
				raise RuntimeError(f"Unknown EI_CLASS = {e_ident['EI_CLASS']}")

			bm.seek(self.ehdr["e_phoff"])

			self.phdrs = []
			self.shdrs = []

			for _ in range(self.ehdr["e_phnum"]):
				elf_phdr = bm.readStruct(Elf_Phdr, endian = endian)
				self.phdrs.append(elf_phdr)

			bm.seek(self.ehdr["e_shoff"])
			for _ in range(self.ehdr["e_shnum"]):
				elf_shdr = bm.readStruct(Elf_Shdr, endian = endian)
				self.shdrs.append(elf_shdr)

	def debug(self, res):
		global args
		if not args["silent"]:
			print("EHDR")
			print(res["ELF"]["ehdr"])
			print("PHDR")
			for phdr in res["ELF"]["phdrs"]:
				print(phdr)
			print("SHDR")
			for shdr in res["ELF"]["shdrs"]:
				print(shdr)

	def deserialize(self):
		global args
		res = dict()
		res["ELF"] = dict()
		res["ELF"]["ehdr"] = self.ehdr
		res["ELF"]["phdrs"] = self.phdrs
		res["ELF"]["shdrs"] = self.shdrs

		self.debug(res)
		
		return res

	def serialize(self):
		with BinaryMarshaller(self.file) as bm:
			if self.e_ident["EI_CLASS"] == ELFCLASS32:
				Elf_Ehdr = Elf32_Ehdr
				Elf_Phdr = Elf32_Phdr
				Elf_Shdr = Elf32_Shdr
			elif self.e_ident["EI_CLASS"] == ELFCLASS64:
				Elf_Ehdr = Elf64_Ehdr
				Elf_Phdr = Elf64_Phdr
				Elf_Shdr = Elf64_Shdr
			else:
				raise RuntimeError(f"Unknown EI_CLASS = {e_ident['EI_CLASS']}")

			endian = self.e_ident["EI_DATA"]

			bm.writeStruct(self.ehdr, Elf_Ehdr)
			bm.seek(self.ehdr["e_phoff"])

			for i in range(self.ehdr["e_phnum"]):
				bm.writeStruct(self.phdrs[i], Elf_Phdr, endian = endian)

			bm.seek(self.ehdr["e_shoff"])
			for i in range(self.ehdr["e_shnum"]):
				bm.writeStruct(self.shdrs[i], Elf_Shdr, endian = endian)

			res = self.deserialize()

			self.debug(res)

			self.file = io.BytesIO(bm.file.getbuffer().tobytes())

	def read(self):
		self.serialize()
		return self.file.getbuffer().tobytes()

def main(input_file, output_file, out_json = False, silent = False):
	elf = ELF(input_file)

	if out_json:
		if not output_file:
			basename = os.path.basename(input_file)
			output_file = f"{basename}.json"
		deserialized_elf = elf.deserialize()
		elf_json = json.dumps(json.loads(demjson3.encode(deserialized_elf)), indent = 4)
		open(output_file, "wb").write(elf_json.encode("latin-1"))
	else:
		if not output_file:
			basename = os.path.basename(input_file)
			output_file = f"{basename}_modified"
		open(output_file, "wb").write(elf.read())

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "Parse an ELF file")
	parser.add_argument("-f", "--file", help = "input file", required = True)
	parser.add_argument("-j", "--json", help = "dump to JSON", action = argparse.BooleanOptionalAction)
	parser.add_argument("-s", "--silent", help = "disable debug information", action = argparse.BooleanOptionalAction)
	parser.add_argument("-o", "--output", help = "output file", nargs = '?', type = str)
	args = vars(parser.parse_args())
	main(args["file"], args["output"], out_json = args["json"], silent = args["silent"])