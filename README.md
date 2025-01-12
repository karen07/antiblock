# AntiBlock
AntiBlock program proxies DNS requests. The IP addresses of the specified domains are added to the routing table for routing through the specified interface.
## Usage
```sh
Commands:
  At least one parameters needs to be filled:
    -url      https://example.com  Domains file URL
    -file     /example.txt         Domains file path
  Required parameters:
    -listen   0.0.0.0:00           Listen address
    -DNS      0.0.0.0:00           DNS address
    -gateway  0.0.0.0              Gateway IP
  Optional parameters:
    -log                           Show operations log
    -stat                          Show statistics data
    -output   /example/            Log or statistics output folder
```
## Article
You can read about the method in the [article](https://habr.com/ru/articles/847412/).
