# PrplMesh D-WPAL

## License

(c) 2019 Intel Corporation

See [LICENSE](LICENSE) for the current license terms of this component.
D-WPAL also uses files from the hostap project (<https://w1.fi/hostapd/)> its license applies as well.

## Building

Development files for the following additional libraries are required:

* libnl3 (3.0) (`sudo apt install libnl-genl-3-dev`)
* [safec](https://github.com/rurban/safeclib) revision ab130d7376267b6deb55e194746fc08d045afa61
* readline (`sudo apt-get install libreadline-dev`) (TODO: should be removed)
* hostap sources

## Using GNU Make (TODO: should be removed)

Type `make` to build. The libnl3 and safec includes and libs are found through pkg-config.
If that doesn't provide the appropriate directories, they can be
specified with `libnl3_cflags`, `libnl3_libs`, `safec_cflags` and `safec_libs`.
readline must be present in the standard include paths, or else CFLAGS must be
set to point to its include directory. hostap sources are expected in
`../hostap`. Set `hostap_dir` if they are in a different directory.

## Using CMAKE

Since currently both GNU Make and CMAKE build systems supported, out of tree build is recommended.
Assuming safec is built and installed to ../../multiap/build/install, the following commands prepares, builds and installs
dwpal library and cli:

```bash
cmake -B./build -H. -DCMAKE_INSTALL_PREFIX=../../multiap/build/install
cmake --build build -- install -j
```