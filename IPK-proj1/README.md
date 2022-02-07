# IPK
Basic lightweight socket server implemented in C++

## Compile and run
```console
$ make
$ ./hinfosvc [port]
```

## Example how to run socket server
```console
$ ./hinfosvc 12345
```

On background:

```console
$ ./hinfosvc 12345 &
```

## Test connection
```console
$ curl http://localhost:12345/hostname
$ curl http://localhost:12345/cpu-name
$ curl http://localhost:12345/load
```
