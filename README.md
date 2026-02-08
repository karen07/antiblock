# AntiBlock
AntiBlock sniffs DNS traffic, extracts IP addresses from DNS responses for specified domains, and dynamically adds routes to direct traffic via selected network interfaces.
## Usage
```c
Commands:
  It is necessary to enter from 1 to 32 values:
    Route domains from path/url through gateway:
      -r  "gateway1 https://test1.com"
      -r  "gateway2 /test1.txt"
      -r  "gateway2 /test2.txt"
      -r  "gateway1 https://test2.com"
      .....................................
  Required parameters:
    -l  "x.x.x.x:xx"  Address for sniffing packets with this src
  Optional parameters:
    -b  "/test.txt"   Subnets not add to the routing table
    -o  "/test/"      Log or stat output folder
    --log             Show operations log
    --stat            Show statistics data
    --test            Test mode
```
## Article
You can read about the method in the [article](https://habr.com/ru/articles/847412/).
