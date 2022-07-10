/*
 * Copyright (c) 1999-2010 Apple Inc.  All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
#ifndef _MACHO_LOADER_H_
#define _MACHO_LOADER_H_

/*
 * This file describes the format of mach object files.
 */
#include <stdbool.h>
#include <stdint.h>

#include "utils.h"

typedef uint32_t cpu_type_t;
typedef uint32_t cpu_subtype_t;
typedef int vm_prot_t;

#define CANARY_MACHO_STR_1 "___stack_chk_fail"
#define CANARY_MACHO_STR_2 "___stack_chk_guard"
#define ARC_STR "_objc_release"
#ifndef FORTIFY_SUFFIX
#define FORTIFY_SUFFIX "_chk"
#endif

#define MH_MAGIC 0xfeedface              /* the mach magic number */
#define MH_CIGAM 0xcefaedfe              /* NXSwapInt(MH_MAGIC) */
#define MH_MAGIC_64 0xfeedfacf           /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe           /* NXSwapInt(MH_MAGIC_64) */
#define MH_ALLOW_STACK_EXECUTION 0x20000 /* NX bit */
#define FAT_MAGIC 0xcafebabe             /* the fat magic number */
#define FAT_CIGAM 0xbebafeca             /* NXSwapLong(FAT_MAGIC) */
#define FAT_MAGIC_64 0xcafebabf          /* the 64-bit fat magic number */
#define FAT_CIGAM_64 0xbfbafeca          /* NXSwapLong(FAT_MAGIC_64) */
/*
  When this bit is set, the OS will
        load the main executable at a
        random address.  Only used in
        MH_EXECUTE filetypes.
*/
#define MH_PIE 0x200000

/*
 * Capability bits used in the definition of cpu_type.
 */
#define CPU_ARCH_MASK 0xff000000  /* mask for architecture bits */
#define CPU_ARCH_ABI64 0x01000000 /* 64 bit ABI */
#define CPU_ARCH_ABI64_32 \
  0x02000000 /* ABI for 64-bit hardware with 32-bit types; LP32 */

#define CPU_TYPE_ARM ((cpu_type_t)12)
#define CPU_TYPE_X86 ((cpu_type_t)7)
#define CPU_TYPE_I386 CPU_TYPE_X86 /* compatibility */
#define CPU_TYPE_X86_64 (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM64 (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM64_32 (CPU_TYPE_ARM | CPU_ARCH_ABI64_32)

#define CPU_SUBTYPE_MASK 0xff000000 /* mask for feature flags */
#define CPU_SUBTYPE_LITTLE_ENDIAN ((cpu_subtype_t)0)
#define CPU_SUBTYPE_BIG_ENDIAN ((cpu_subtype_t)1)
#define CPU_TYPE_ANY ((cpu_type_t)-1)

/*
 * After MacOS X 10.1 when a new load command is added that is required to be
 * understood by the dynamic linker for the image to execute properly the
 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
 * linker sees such a load command it it does not understand will issue a
 * "unknown load command required for execution" error and refuse to use the
 * image.  Other load commands without this bit that are not understood will
 * simply be ignored.
 */
#define LC_REQ_DYLD 0x80000000
/* Constants for the cmd field of all load commands, the type */
#define LC_SEGMENT 0x1         /* segment of this file to be mapped */
#define LC_SYMTAB 0x2          /* link-edit stab symbol table info */
#define LC_DYSYMTAB 0xb        /* dynamic link-edit symbol table info */
#define LC_LOAD_DYLIB 0xc      /* load a dynamically linked shared library */
#define LC_LOAD_DYLINKER 0xe   /* load a dynamic linker */
#define LC_SEGMENT_64 0x19     /* 64-bit segment of this file to be mapped */
#define LC_CODE_SIGNATURE 0x1d /* local of code signature */
#define LC_DYLD_INFO 0x22      /* compressed dyld information */
#define LC_DYLD_INFO_ONLY \
  (0x22 | LC_REQ_DYLD)                /* compressed dyld information only */
#define LC_MAIN (0x28 | LC_REQ_DYLD)  /* replacement for LC_UNIXTHREAD */
#define LC_ENCRYPTION_INFO 0x21       /* encrypted segment information */
#define LC_ENCRYPTION_INFO_64 0x2C    /* 64-bit encrypted segment information */
#define LC_RPATH (0x1c | LC_REQ_DYLD) /* runpath additions */

union lc_str {
  uint32_t offset; /* offset to the string */
};

typedef struct macho_prot {
  // Code Signature (codesign)
  bool code_signature;
  // Encrypted (`LC_ENCRYPTION_INFO`/`LC_ENCRYPTION_INFO_64`)
  bool encrypted;
  // Automatic Reference Counting
  bool arc;
  bool nx;
  bool canary;
  char* rpath;
  int pie;
  int fortify;
} macho_prot_t;

typedef struct macho_arch {
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
} macho_arch_t;

typedef struct macho_ctx {
  file_load_t* file_load;
  macho_prot_t macho_prot;
  macho_arch_t macho_arch;
} macho_ctx_t;

/*
 * The 32-bit mach header appears at the very beginning of the object file for
 * 32-bit architectures.
 */
typedef struct mach_header {
  uint32_t magic;           /* mach magic number identifier */
  cpu_type_t cputype;       /* cpu specifier */
  cpu_subtype_t cpusubtype; /* machine specifier */
  uint32_t filetype;        /* type of file */
  uint32_t ncmds;           /* number of load commands */
  uint32_t sizeofcmds;      /* the size of all the load commands */
  uint32_t flags;           /* flags */
} mach_header_t;

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
typedef struct mach_header_64 {
  uint32_t magic;           /* mach magic number identifier */
  cpu_type_t cputype;       /* cpu specifier */
  cpu_subtype_t cpusubtype; /* machine specifier */
  uint32_t filetype;        /* type of file */
  uint32_t ncmds;           /* number of load commands */
  uint32_t sizeofcmds;      /* the size of all the load commands */
  uint32_t flags;           /* flags */
  uint32_t reserved;        /* reserved */
} mach_header_64_t;

typedef struct fat_header {
  uint32_t magic;     /* FAT_MAGIC */
  uint32_t nfat_arch; /* number of structs that follow */
} fat_header_t;

typedef struct fat_arch {
  cpu_type_t cputype;       /* cpu specifier (int) */
  cpu_subtype_t cpusubtype; /* machine specifier (int) */
  uint32_t offset;          /* file offset to this object file */
  uint32_t size;            /* size of this object file */
  uint32_t align;           /* alignment as a power of 2 */
} fat_arch_t;

typedef struct fat_arch_64 {
  cpu_type_t cputype;       /* cpu specifier (int) */
  cpu_subtype_t cpusubtype; /* machine specifier (int) */
  uint64_t offset;          /* file offset to this object file */
  uint64_t size;            /* size of this object file */
  uint32_t align;           /* alignment as a power of 2 */
  uint32_t reserved;        /* reserved */
} fat_arch_64_t;

/*
 * The load commands directly follow the mach_header.  The total size of all
 * of the commands is given by the sizeofcmds field in the mach_header.  All
 * load commands must have as their first two fields cmd and cmdsize.  The cmd
 * field is filled in with a constant for that command type.  Each command type
 * has a structure specifically for it.  The cmdsize field is the size in bytes
 * of the particular load command structure plus anything that follows it that
 * is a part of the load command (i.e. section structures, strings, etc.).  To
 * advance to the next load command the cmdsize can be added to the offset or
 * pointer of the current load command.  The cmdsize for 32-bit architectures
 * MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a multiple
 * of 8 bytes (these are forever the maximum alignment of any load commands).
 * The padded bytes must be zero.  All tables in the object file must also
 * follow these rules so the file can be memory mapped.  Otherwise the pointers
 * to these tables will not work well or at all on some machines.  With all
 * padding zeroed like objects will compare byte for byte.
 */
typedef struct load_command {
  uint32_t cmd;     /* type of load command */
  uint32_t cmdsize; /* total size of command in bytes */
} load_command_t;

typedef struct segment_command { /* for 32-bit architectures */
  uint32_t cmd;                  /* LC_SEGMENT */
  uint32_t cmdsize;              /* includes sizeof section structs */
  char segname[16];              /* segment name */
  uint32_t vmaddr;               /* memory address of this segment */
  uint32_t vmsize;               /* memory size of this segment */
  uint32_t fileoff;              /* file offset of this segment */
  uint32_t filesize;             /* amount to map from the file */
  vm_prot_t maxprot;             /* maximum VM protection */
  vm_prot_t initprot;            /* initial VM protection */
  uint32_t nsects;               /* number of sections in segment */
  uint32_t flags;                /* flags */
} segment_command_t;

typedef struct segment_command_64 { /* for 64-bit architectures */
  uint32_t cmd;                     /* LC_SEGMENT_64 */
  uint32_t cmdsize;                 /* includes sizeof section_64 structs */
  char segname[16];                 /* segment name */
  uint64_t vmaddr;                  /* memory address of this segment */
  uint64_t vmsize;                  /* memory size of this segment */
  uint64_t fileoff;                 /* file offset of this segment */
  uint64_t filesize;                /* amount to map from the file */
  vm_prot_t maxprot;                /* maximum VM protection */
  vm_prot_t initprot;               /* initial VM protection */
  uint32_t nsects;                  /* number of sections in segment */
  uint32_t flags;                   /* flags */
} segment_command_64_t;

typedef struct section { /* for 32-bit architectures */
  char sectname[16];     /* name of this section */
  char segname[16];      /* segment this section goes in */
  uint32_t addr;         /* memory address of this section */
  uint32_t size;         /* size in bytes of this section */
  uint32_t offset;       /* file offset of this section */
  uint32_t align;        /* section alignment (power of 2) */
  uint32_t reloff;       /* file offset of relocation entries */
  uint32_t nreloc;       /* number of relocation entries */
  uint32_t flags;        /* flags (section type and attributes)*/
  uint32_t reserved1;    /* reserved (for offset or index) */
  uint32_t reserved2;    /* reserved (for count or sizeof) */
} section_t;

typedef struct section_64 { /* for 64-bit architectures */
  char sectname[16];        /* name of this section */
  char segname[16];         /* segment this section goes in */
  uint64_t addr;            /* memory address of this section */
  uint64_t size;            /* size in bytes of this section */
  uint32_t offset;          /* file offset of this section */
  uint32_t align;           /* section alignment (power of 2) */
  uint32_t reloff;          /* file offset of relocation entries */
  uint32_t nreloc;          /* number of relocation entries */
  uint32_t flags;           /* flags (section type and attributes)*/
  uint32_t reserved1;       /* reserved (for offset or index) */
  uint32_t reserved2;       /* reserved (for count or sizeof) */
  uint32_t reserved3;       /* reserved */
} section_64_t;

typedef struct symtab_command {
  uint32_t cmd;     /* LC_SYMTAB */
  uint32_t cmdsize; /* sizeof(struct symtab_command) */
  uint32_t symoff;  /* symbol table offset */
  uint32_t nsyms;   /* number of symbol table entries */
  uint32_t stroff;  /* string table offset */
  uint32_t strsize; /* string table size in bytes */
} symtab_command_t;

/*
 * Format of a symbol table entry of a Mach-O file for 32-bit architectures.
 * Modified from the BSD format.  The modifications from the original format
 * were changing n_other (an unused field) to n_sect and the addition of the
 * N_SECT type.  These modifications are required to support symbols in a larger
 * number of sections not just the three sections (text, data and bss) in a BSD
 * file.
 */
typedef struct nlist {
  union {
    uint32_t n_strx; /* index into the string table */
  } n_un;
  uint8_t n_type;   /* type flag, see below */
  uint8_t n_sect;   /* section number or NO_SECT */
  int16_t n_desc;   /* see <mach-o/stab.h> */
  uint32_t n_value; /* value of this symbol (or stab offset) */
} nlist_t;

/*
 * This is the symbol table entry structure for 64-bit architectures.
 */
typedef struct nlist_64 {
  union {
    uint32_t n_strx; /* index into the string table */
  } n_un;
  uint8_t n_type;   /* type flag, see below */
  uint8_t n_sect;   /* section number or NO_SECT */
  uint16_t n_desc;  /* see <mach-o/stab.h> */
  uint64_t n_value; /* value of this symbol (or stab offset) */
} nlist_64_t;

/*
 * The rpath_command contains a path which at runtime should be added to
 * the current run path used to find @rpath prefixed dylibs.
 */
typedef struct rpath_command {
  uint32_t cmd;      /* LC_RPATH */
  uint32_t cmdsize;  /* includes string */
  union lc_str path; /* path to add to run path */
} rpath_command_t;

/*
 * This is the second set of the symbolic information which is used to support
 * the data structures for the dynamically link editor.
 *
 * The original set of symbolic information in the symtab_command which contains
 * the symbol and string tables must also be present when this load command is
 * present.  When this load command is present the symbol table is organized
 * into three groups of symbols:
 *	local symbols (static and debugging symbols) - grouped by module
 *	defined external symbols - grouped by module (sorted by name if not lib)
 *	undefined external symbols (sorted by name if MH_BINDATLOAD is not set,
 *	     			    and in order the were seen by the static
 *				    linker if MH_BINDATLOAD is set)
 * In this load command there are offsets and counts to each of the three groups
 * of symbols.
 *
 * This load command contains a the offsets and sizes of the following new
 * symbolic information tables:
 *	table of contents
 *	module table
 *	reference symbol table
 *	indirect symbol table
 * The first three tables above (the table of contents, module table and
 * reference symbol table) are only present if the file is a dynamically linked
 * shared library.  For executable and object modules, which are files
 * containing only one module, the information that would be in these three
 * tables is determined as follows:
 * 	table of contents - the defined external symbols are sorted by name
 *	module table - the file contains only one module so everything in the
 *		       file is part of the module.
 *	reference symbol table - is the defined and undefined external symbols
 *
 * For dynamically linked shared library files this load command also contains
 * offsets and sizes to the pool of relocation entries for all sections
 * separated into two groups:
 *	external relocation entries
 *	local relocation entries
 * For executable and object modules the relocation entries continue to hang
 * off the section structures.
 */
typedef struct dysymtab_command {
  uint32_t cmd;     /* LC_DYSYMTAB */
  uint32_t cmdsize; /* sizeof(struct dysymtab_command) */
  /*
   * The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
   * are grouped into the following three groups:
   *    local symbols (further grouped by the module they are from)
   *    defined external symbols (further grouped by the module they are from)
   *    undefined symbols
   *
   * The local symbols are used only for debugging.  The dynamic binding
   * process may have to use them to indicate to the debugger the local
   * symbols for a module that is being bound.
   *
   * The last two groups are used by the dynamic binding process to do the
   * binding (indirectly through the module table and the reference symbol
   * table when this is a dynamically linked shared library file).
   */
  uint32_t ilocalsym; /* index to local symbols */
  uint32_t nlocalsym; /* number of local symbols */

  uint32_t iextdefsym; /* index to externally defined symbols */
  uint32_t nextdefsym; /* number of externally defined symbols */

  uint32_t iundefsym; /* index to undefined symbols */
  uint32_t nundefsym; /* number of undefined symbols */
  /*
   * For the for the dynamic binding process to find which module a symbol
   * is defined in the table of contents is used (analogous to the ranlib
   * structure in an archive) which maps defined external symbols to modules
   * they are defined in.  This exists only in a dynamically linked shared
   * library file.  For executable and object modules the defined external
   * symbols are sorted by name and is use as the table of contents.
   */
  uint32_t tocoff; /* file offset to table of contents */
  uint32_t ntoc;   /* number of entries in table of contents */
  /*
   * To support dynamic binding of "modules" (whole object files) the symbol
   * table must reflect the modules that the file was created from.  This is
   * done by having a module table that has indexes and counts into the merged
   * tables for each module.  The module structure that these two entries
   * refer to is described below.  This exists only in a dynamically linked
   * shared library file.  For executable and object modules the file only
   * contains one module so everything in the file belongs to the module.
   */
  uint32_t modtaboff; /* file offset to module table */
  uint32_t nmodtab;   /* number of module table entries */
  /*
   * To support dynamic module binding the module structure for each module
   * indicates the external references (defined and undefined) each module
   * makes.  For each module there is an offset and a count into the
   * reference symbol table for the symbols that the module references.
   * This exists only in a dynamically linked shared library file.  For
   * executable and object modules the defined external symbols and the
   * undefined external symbols indicates the external references.
   */
  uint32_t extrefsymoff; /* offset to referenced symbol table */
  uint32_t nextrefsyms;  /* number of referenced symbol table entries */
  /*
   * The sections that contain "symbol pointers" and "routine stubs" have
   * indexes and (implied counts based on the size of the section and fixed
   * size of the entry) into the "indirect symbol" table for each pointer
   * and stub.  For every section of these two types the index into the
   * indirect symbol table is stored in the section header in the field
   * reserved1.  An indirect symbol table entry is simply a 32bit index into
   * the symbol table to the symbol that the pointer or stub is referring to.
   * The indirect symbol table is ordered to match the entries in the section.
   */
  uint32_t indirectsymoff; /* file offset to the indirect symbol table */
  uint32_t nindirectsyms;  /* number of indirect symbol table entries */
  /*
   * To support relocating an individual module in a library file quickly the
   * external relocation entries for each module in the library need to be
   * accessed efficiently.  Since the relocation entries can't be accessed
   * through the section headers for a library file they are separated into
   * groups of local and external entries further grouped by module.  In this
   * case the presents of this load command who's extreloff, nextrel,
   * locreloff and nlocrel fields are non-zero indicates that the relocation
   * entries of non-merged sections are not referenced through the section
   * structures (and the reloff and nreloc fields in the section headers are
   * set to zero).
   *
   * Since the relocation entries are not accessed through the section headers
   * this requires the r_address field to be something other than a section
   * offset to identify the item to be relocated.  In this case r_address is
   * set to the offset from the vmaddr of the first LC_SEGMENT command.
   * For MH_SPLIT_SEGS images r_address is set to the the offset from the
   * vmaddr of the first read-write LC_SEGMENT command.
   *
   * The relocation entries are grouped by module and the module table
   * entries have indexes and counts into them for the group of external
   * relocation entries for that the module.
   *
   * For sections that are merged across modules there must not be any
   * remaining external relocation entries for them (for merged sections
   * remaining relocation entries must be local).
   */
  uint32_t extreloff; /* offset to external relocation entries */
  uint32_t nextrel;   /* number of external relocation entries */
  /*
   * All the local relocation entries are grouped together (they are not
   * grouped by their module since they are only used if the object is moved
   * from it staticly link edited address).
   */
  uint32_t locreloff; /* offset to local relocation entries */
  uint32_t nlocrel;   /* number of local relocation entries */
} dysymtab_command_t;

/*
 * Identify the byte order
 * of the current host.
 */

enum NXByteOrder { NX_UnknownByteOrder, NX_LittleEndian, NX_BigEndian };

// load
int macho_load(file_load_t* file_ctx);
int macho_fat_load(file_load_t* file_ctx);
#endif