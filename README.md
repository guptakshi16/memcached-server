# memcached-server
Minimal memcached server program based on libevent implementing get/set binary protocol 

## Steps to compile
1. Install libevent library

- sudo apt-get install libevent-dev
or
- install from source http://libevent.org

2. make

## Steps to run/test
1. Runs the server on port listening on port 11211
 ./memcached-server 11211

2. Use bmemcached library to test
 https://github.com/jaysonsantos/python-binary-memcached

## Limitations
* Max Key size 256 bytes
* Max Val size 512 bytes
* Single threaded - No locking
