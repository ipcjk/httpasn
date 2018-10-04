**httpasn**

httpasn sends out a http redirect based on the clients ip source network aka autonomous system. Therefore
you can redirect users to a cache or cdn near the end-user.

Please run init.sh before the first run to download an ip to asn - database file.

**configuration file**

Please see the redirects.txt for a full configuration example. Basically it is a CSV file with URIs
and AS-numbers to match. When a certain AS is not found, it will default to the AS-number 0 redirect line.
  

_attention_: work in progress   / proof of concept