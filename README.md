# Celebi

*Crystal + Mythic = Celebi*

A Mythic agent for x64 Windows that uses [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html) to build its payloads as position-independent shellcode.

---

## Credits

**Celebi was originally written by [@ofasgard (Callum Murphy-Hale)](https://github.com/ofasgard).**

The original author's work builds on the efforts of:

- [Raphael Mudge](https://tradecraftgarden.org/crystalpalace.html) — Crystal Palace and LibTCG.
- [@pard0p](https://github.com/pard0p/LibWinHttp) — the LibWinHttp library used for HTTP messaging.
- [Cody Thomas](https://github.com/its-a-feature) — Mythic, and its excellent documentation.
- [Leonardo Tamiano](https://blog.leonardotamiano.xyz/tech/base64/) — a self-contained base64 implementation that plays nicely with PIC.
- [TrustedSec](https://github.com/trustedsec/CS-Situational-Awareness-BOF) — open-source BOFs ported into PICOs for some of Celebi's built-in commands.

This repository is a port and extension of the original project. **Most of the new code was written by an AI agent under direct human supervision**; the original author's design and code are preserved and remain the foundation of the project.

---

## Disclaimer

> This project is released strictly for educational purposes, and is intended solely for use by authorised parties performing legitimate security research and red team assessments. My only intention is to share my work for the purposes of uplifting security.

This agent is a work in progress and is **not opsec safe**. Please don't use it in a real red team engagement.

---

## Original features

- Performs a plaintext checkin with the specified C2 server via HTTP(S).
- Supports the `callback_host` and `callback_port` parameters to specify the C2 listener, and the `post_uri` parameter to specify the URI for checking in.
- Built-in commands: `exit`, `whoami`, `sleep`, `register`, `unregister`, `execute_pico`, `morph`.
- `register`/`unregister` upload or delete files from the agent's in-memory vault; `execute_pico` interprets a registered file as a Crystal Palace PICO and runs it; `morph` hotswaps the PICO behind a built-in command.
- XOR-based sleepmasking of the memory vault, implemented as a PICO so it can be swapped out; a PICO hook is also provided for sleepmasking the executable PIC itself.
- Built-in PICOs: `checkin` (situational awareness), `whoami` (ported from TrustedSec's BOF), `mask_vault` / `mask_sleep` (sleepmasking).
- The agent is designed around dynamically loaded capabilities: upload new PICO functionality with `register` and swap built-ins with `morph` — no recompiling the shellcode.

## Added features (Mythic v4 port, 2026)

- **Mythic v4 compatibility** — updated container libraries and translation-container wire format; `mythic_encrypts=False` with an **AES256-HMAC** envelope (`aes256_hmac`).
- **RSA Encrypted Key Exchange (EKE)** — optional `encrypted_exchange_check` staging via `staging_rsa` (bcrypt RSA-4096, OAEP-SHA1) with per-session keys.
- **Full http C2 profile support** — callback host/port, HTTPS toggle, post/get URIs, query parameter name, callback interval, jitter, killdate, headers, proxy.
- **P2P (smb/tcp C2 profiles)** — `link` / `unlink` commands. P2P children bind a named pipe (`smb`) or TCP listener (`tcp`) and check in through the relaying agent; **multi-link chaining** lets agents pivot deeper (`parent -> smb -> tcp -> ...`) with Mythic delegate traffic and automatic callback-graph edges.
- **`spawn` / `spawnto`** — build a new payload on demand (http/smb/tcp) via Mythic RPC, download it through the agent's own channel (works over http *and* through the p2p relay) and inject it into a sacrificial process. Spawned tcp children use a random high port (45621–59832); the parent verifies the port is free before injecting.
- **Checkin IP reporting** — the agent reports its host's local IPv4 at checkin.

New commands: `link`, `unlink`, `spawn`, `spawnto` — alongside the original `exit`, `whoami`, `sleep`, `register`, `unregister`, `execute_pico`, `morph`.

## Installation

### Via mythic-cli

```console
$ ./mythic-cli install github https://github.com/garlic-wizard/celebi
```

This installs the `celebi` payload type and the `celebi_translator` translation container. Build payloads with the http, smb or tcp C2 profiles, `AESPSK` set to `aes256_hmac`, and `encrypted_exchange_check` enabled for the p2p profiles.

### Manually

1. Clone the repository and copy both `celebi` and `celebi_translator` to your `Mythic/InstalledServices` folder.
2. `mythic-cli add celebi` and `mythic-cli add celebi_translator`.
3. `mythic-cli build celebi` and `mythic-cli build celebi_translator`.
4. Build payloads using the http, smb or tcp C2 profile.

## Design

The overall design goal of Celebi is to hardcode as little functionality as possible: basic functionality such as sleep masking, information gathering, and command execution live in a set of PICOs linked into the final implant. The PICOs that ship with Celebi "just work" without being opsec safe, but they can be replaced with your own Crystal Palace PICOs implementing the same interfaces.

The extension work keeps that philosophy: the new p2p and spawn capabilities are implemented as plain commands plus a small wire-format extension, with no changes to the PICO model.

## Example: Executing a PICO

The function signature for a generic PICO that Celebi knows how to execute is:

```c
typedef char *(*GENERIC_PICO)(char *cmdline, size_t len);
```

Here's an example of a very simple PICO that implements this interface:

```c
#include <windows.h>

WINBASEAPI VOID WINAPI KERNEL32$OutputDebugStringA (LPCSTR lpOutputString);

char *go(char * arg, size_t len) {
    KERNEL32$OutputDebugStringA(arg);
    return "printed a debug string!";
}
```

Compile it into a 64-bit COFF with MinGW and link it with Crystal Palace:

```text
x64:
	load "dbg_pico.o"
	make object
	export
```

```console
$ piclink linker.spec x64 dbg_pico.bin
```

Then use `register` to upload the PICO and `execute_pico` to invoke it.
