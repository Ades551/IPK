# IPK - socket server
Basic lightweight socket server implemented in C++

## Author
[Adam Rajko ( xrajko00 )](https://github.com/Ades551/)

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

## Rating
|               | Points |
| :------------ | :----: |
| Good requests | 10/10  |
| Bad requests  |  7/7   |
| Documentation |  2/3   |
| Overall       | 19/20  |
