# iolatency

Homework for EECS 6891 Extensible Operating Systems.

To run, run `make` and then `sudo ./iolatency <print interval (s)>`.

For example, the following will print output every 3 seconds.

```console
$ sudo ./iolatency 3
     usecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 1        |*************                           |
        64 -> 127        : 1        |*************                           |
       128 -> 255        : 3        |****************************************|
       256 -> 511        : 2        |**************************              |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 1        |*************                           |

     usecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 1        |****************************************|
       128 -> 255        : 1        |****************************************|
       256 -> 511        : 1        |****************************************|
```
