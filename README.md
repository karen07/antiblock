# AntiBlock
AntiBlock program proxies DNS requests. The IP addresses of the specified domains are added to the routing table for routing through the specified interfaces.
## Usage
```sh
Commands:
  At least one parameters needs to be filled:
    -domains  "test1 https://test1.com"  Route domains from path/url through gateway
    -domains  "test2 /test1.txt"         Route domains from path/url through gateway
    -domains  "test3 /test2.txt"         Route domains from path/url through gateway
    -domains  "test4 https://test2.com"  Route domains from path/url through gateway
    ........
  Required parameters:
    -listen    x.x.x.x:xx                Listen address
    -DNS       x.x.x.x:xx                DNS address
  Optional parameters:
    -output    /test/                    Log or statistics output folder
    -log                                 Show operations log
    -stat                                Show statistics data
```
## Article
You can read about the method in the [article](https://habr.com/ru/articles/847412/).
