
## about revealhashed-python v0.1.2
revealhashed is a streamlined utility to correlate ntds usernames, nt hashes, and cracked passwords in one view while cutting out time-consuming manual tasks.

## how to install
from pypi:  
`pipx install revealhashed`

from github:  
`pipx install git+https://github.com/crosscutsaw/revealhashed-python`

## don't want to install?

grab revealhashed binary from [releases](https://github.com/crosscutsaw/revealhashed-python/releases/latest) section.

## how to use
```
revealhashed v0.1.2

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
this command executes [zblurx's ntdsutil.py](https://github.com/zblurx/ntdsutil.py) to dump ntds safely then does classic revealhashed operations.

-w (wordlist) switch is needed. one or more wordlists can be supplied.    
-e (enabled-only) switch is not needed but suggested. it's self explanatory; only shows enabled users.  

for example:  
`revealhashed dump 'troupe.local/emreda:Aa123456'@192.168.2.11 -w wordlist1.txt wordlist2.txt -e`

### revealhashed reveal
this command wants to get supplied with ntds file by user then does classic revealhashed operations.  
_ntds file should contain usernames and hashes. it should be not ntds.dit. example ntds dump can be obtained from repo_

-ntds or -nxc switch is needed. -ntds switch is for a file you own with hashes. -nxc switch is for scanning ~/.nxc/logs/ntds then selecting .ntds file.
-w (wordlist) switch is needed. one or more wordlists can be supplied.  
-e (enabled-only) switch is not needed but suggested. it's self explanatory; only shows enabled users.  

for example:  
`revealhashed reveal -ntds TROUPEDC_192.168.2.11_2025-05-12_123035.ntds -w wordlist1.txt -e`

## example outputs
![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp1.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp2.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp3.PNG)
