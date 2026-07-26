# bof2pico

Helper utility for converting a compiled BOF into a PICO that celebi is able to execute. Adapted from [Simple BOF Runner](https://tradecraftgarden.org/simplebof.html) by Raphael Mudge, and reproduces the `bofapi.c` file in its entirety.

To convert a BOF into a PICO with no hardcoded arguments:

```sh
$ ./bof2pico.py /path/to/whoami.x64.o whoami.x64.pico
```

To convert a BOF into a PICO with hardcoded arguments:

```sh
$ ./bof2pico.py /path/to/dir.x64.o dir.x64.pico 'z:C:\Users\Wirt'
```

Prefix each argument with a format specifier so that we understand how to convert it into a datatype that's compatible with the BOF argument format:

- `z`: A UTF-8 encoded string.
- `Z`: A UTF-16 encoded "wide" string.
- `i`: A 4-byte integer value.
- `s`: A 2-byte short value.
