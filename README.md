# Client DNS

Acest program este un client DNS simplu care permite rezolvarea numelor de domenii în adrese IP și invers.

## Cerințe

- Python 3.x
- Biblioteca dnspython: `pip install dnspython`

## Comenzi

```
resolve <domeniu/IP> - rezolvă un domeniu în IP sau un IP în domeniu
use dns <IP> - schimbă serverul DNS utilizat pentru rezolvare
```

## Exemple

```
resolve google.com
resolve 8.8.8.8
use dns 1.1.1.1
```
