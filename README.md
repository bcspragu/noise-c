Note: This fork is an attempt to compile a recent version of Noise-C to WASM with Emscripten, and add some project-specific bindings to expose a minimal surface area. I don't expect anything in this fork to be generally useful.

TODO

- [ ] Try compiling `src/noise-c.c` with WASM
- [ ] Figure out the interface we need to expose for our handshake/message sending

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
