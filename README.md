# echeck

Echeck is a platform generic tool designed to check binary protections enabled

## Installation

```bash
git clone https://github.com/R3tr074/echeck.git && cd echeck
make && sudo cp build/linux/x86_64/release/echeck /usr/bin/echeck
```

You can use the [xmake](https://xmake.io/#/) to cross-compile and others.

# Utility

You can format mach-o and ELF's(in the future Windows PE too) for extract a lot util info to exploitation:

```bash
# ELF's
r3tr0@pwnbox:~$ echeck /work/file
[*] '/work/file'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
    FUNCS:    gets system popen
r3tr0@pwnbox:~$ echeck /bin/ls
[*] '/bin/ls'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled (6 functions)
```

```bash
# mach-o's
r3tr0@pwnbox:~$ file macho-ls 
macho-ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>] [arm64e (caps: 0x2):Mach-O 64-bit arm64e (caps: PAC00) executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>]
r3tr0@pwnbox:~$ echeck macho-ls 
[*] 'macho-ls'
    Arch:      amd64-64-little
    Stack:     Canary found
    NX:        NX enabled
    PIE:       PIE enabled
    ARC:       No ARC
    ENCRYPTED: No encrypted
    CODE SIGN: Signed
[*] 'macho-ls'
    Arch:      aarch-64-little
    Stack:     Canary found
    NX:        NX enabled
    PIE:       PIE enabled
    ARC:       No ARC
    ENCRYPTED: No encrypted
    CODE SIGN: Signed
```

## Todo

1. [x] FORTIFY
2. [x] RUNPATH
3. [x] Interesting imports, like `system()`
4. [x] Dangerous imports, like `gets()`

## References

- readpe:
  - https://github.com/merces/pev
- Protcheck:
  - https://github.com/lockedbyte/protcheck
- pwntools:
  - https://github.com/Gallopsled/pwntools
- radare2
  - https://github.com/radareorg/radare2
- checksec.rs
  - https://github.com/etke/checksec.rs