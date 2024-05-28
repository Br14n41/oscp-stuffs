# Password-Hash Cracking

*Hash Analyzer*: [https://www.tunnelsup.com/hash-analyzer/](https://www.tunnelsup.com/hash-analyzer/) 

*Crackstation*: [https://crackstation.net/](https://crackstation.net/)

## fcrackzip

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip # Cracking zip files
```

## John

> [https://github.com/openwall/john/tree/bleeding-jumbo/run](https://github.com/openwall/john/tree/bleeding-jumbo/run)
> 
- If there’s an encrypted file, try to convert it into john hash and crack.

```bash
ssh2john.py id_rsa > hash
# Convert the obtained hash to John format(above link)
john hashfile --wordlist=rockyou.txt
```

## Hashcat

> [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
> 

```bash
# Obtain the Hash module number 
hashcat -m <number> hash wordlists.txt --force
```