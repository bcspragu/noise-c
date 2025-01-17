Note: This fork is an attempt to compile a recent version of Noise-C to WASM with Emscripten, and add some project-specific bindings to expose a minimal surface area. I don't expect anything in this fork to be generally useful.

Also, while I theoretically can work with C, I don't trust myself in it, so even if you _do_ find this project to be useful, don't use it for anything serious until An Actual Professional has taken a look at it.

For example, I still need to confirm that Emscripten is actually using a reasonable source of entropy for key generation via whatever it's replacing /dev/urandom with.

TODO

- [ ] Figure out how/where to persist state
- [ ] Add message padding support
  - This also requires good randomness, so make sure that part works (see below)
- [ ] Figure out how to build for WASM against libsodium
  - Or figure out if the reference backend is fine for our usecase
- [ ] Make output as small/minimal as possible
- [ ] Figure out if /dev/urandom usage is an acceptable source of entropy in Emscripten
  - Should generate a bunch of random numbers with it and run through some test suite, use different browsers.
- [x] Try calling the WASM from actual JS code
- [x] Try compiling `src/noise-c.c` with WASM
- [x] Figure out the interface we need to expose for our handshake/message sending
  - Still need to document this

## Building WASM

```bash
emconfigure ./configure
emmake make -e CFLAGS='-O3 -g -pthread'

# No idea if this is actually how things should be, I do wonder if I'm just messing up the automake files.
emcc -O3 src/noise-c.o \
  -o output.mjs \
  -sSINGLE_FILE \
  -Lsrc -Lsrc/protocol \
  -lnoise -lnoiseprotocol \
  -sEXPORTED_FUNCTIONS=_start_handshake,_continue_handshake,_finish_handshake,_encrypt_message,_decrypt_message,_malloc,_free \
  -sEXPORTED_RUNTIME_METHODS=cwrap,getValue,UTF8ToString,stringToUTF8 \
  -sMODULARIZE \
  -sENVIRONMENT=web
```

Noise-C Library
===============

Noise-C is a plain C implementation of the
[Noise Protocol](http://noiseprotocol.org), intended as a
reference implementation.  It can also be referred to as "Noisy",
which is what you get when you say "Noise-C" too fast.  The code is
distributed under the terms of the MIT license.

The [documentation](http://rweather.github.io/noise-c/index.html)
contains more information on the library, examples, and how to build it.

For more information on this library, to report bugs, to contribute,
or to suggest improvements, please contact the author Rhys Weatherley via
[email](mailto:rhys.weatherley@gmail.com).
