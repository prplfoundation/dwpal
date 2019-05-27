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
* hostap sources in ../ directory

Assuming safec is built and installed to ../../multiap/build/install, the following commands prepares, builds and installs
dwpal library and cli:

```bash
cmake -B./build -H. -DCMAKE_INSTALL_PREFIX=../../multiap/build/install
cmake --build build -- install -j
```
