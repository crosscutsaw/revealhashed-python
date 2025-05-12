## about revealhashed-python v0.1
revealhashed is a semi-automated python script to automatically match username-hash-password respectively.

## how to install
from pypi:  
`pipx install revealhashed`

from github:  
`pipx install git+https://github.com/crosscutsaw/revealhashed-python`

## how to use
```
revealhashed v0.1

usage: revealhashed [-h] [-r] {dump,reveal} ...

positional arguments:
  {dump,reveal}
    dump         Dump NTDS using ntdsutil then reveal credentials with it
    reveal       Use your own NTDS dump then reveal credentials with it

options:
  -h, --help     show this help message and exit
  -r, --reset    Delete old files in ~/.revealhashed
```
### revealhashed -r
just execute `revealhashed -r` to remove contents of ~/.revealhashed

### revealhashed dump
this command executes [zblurx's ntdsutil.py](https://github.com/zblurx/ntdsutil.py) then does classic revealhashed operations.

-w (wordlist) switch is needed. one or more wordlists can be supplied.    
-e (enabled-only) switch is not needed but suggested. it's self explanatory; only shows enabled users.  

for example: `revealhashed dump 'troupe.local/emreda:Aa123456'@192.168.2.11 -w wordlist1.txt wordlist2.txt -e`

### revealhashed reveal
this command wants to get supplied with ntds file by user then does classic revealhashed operations.

-ntds switch is needed.  
-w (wordlist) switch is needed. one or more wordlists can be supplied.  
-e (enabled-only) switch is not needed but suggested. it's self explanatory; only shows enabled users.  

for example: `revealhashed reveal -ntds ~/Downloads/TROUPEDC_192.168.2.11_2025-05-12_123035.ntds -w ~/Downloads/wordlist1.txt -e`

## example outputs
![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp1.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp2.PNG)
