Example SSL Echo Server
=======================

This is an example demonstrating how to use OpenSSL in order to implement an echo server that communicates encrypted. 

Installation
------------

Make sure that ``libssl`` can be found by your compiling environment, e. g. by installing necessary packages:

```sh
apt-get update
apt-get install build-essential libssl-dev openssl stunnel
```

After that, enjoy the compilation process:


```sh
make
```

Usage
-----

In the following using the SSL echo server on port `8888` using the provided `example.pem` file. 

```sh
./echo_server_ssl 8888 example.pem
```

Optional: if you want to create your own certificate/key file invoke the command and follow the instructions on your screen. Of course, you would have to restart your echo server:
```sh
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout example.pem -out example.pem
```

Now start `stunnel` in order to be able to talk to your SSL echo server:
```sh
stunnel -c -f -P '' -r localhost:8888 -d localhost:2222 
```

Everything that goes to port 2222 is now wrapped into SSL and forwarded to your SSL echo server on port 8888. Therefore, you should now be able to talk to your SSL echo server using ordinary telnet:
```sh
telnet localhost 2222
```

Type something and hit `<Enter>` to get back the server's response. 
