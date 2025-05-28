
## about revealhashed-python v0.1.3
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
revealhashed v0.1.3

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
```
revealhashed v0.1.3

usage: revealhashed dump [-h] [-debug] [-hashes HASHES] [-no-pass] [-k] [-aesKey AESKEY] [-dc-ip DC_IP] [-codec CODEC] -w WORDLIST WORDLIST2 [WORDLIST WORDLIST2 ...] [-e] [-nd] [-csv] target
```

this command executes [zblurx's ntdsutil.py](https://github.com/zblurx/ntdsutil.py) to dump ntds safely then does classic revealhashed operations.  

-w (wordlist) switch is needed. one or more wordlists can be supplied.    
-e (enabled-only) switch is not needed but suggested. it's self explanatory; only shows enabled users.  
-nd (no-domain) switch hides domain names in usernames.  
-csv (csv) switch is self explanatory; saves output to csv instead txt.  

for example:  
`revealhashed dump '<domain>/<username>:<password>'@<dc_ip> -w wordlist1.txt wordlist2.txt -e -nd -csv`

### revealhashed reveal
```
revealhashed v0.1.3

usage: revealhashed reveal [-h] [-ntds NTDS] [-nxc] [-w WORDLIST WORDLIST2 [WORDLIST WORDLIST2 ...]] [-e] [-nd] [-csv]

options:
  -h, --help            show this help message and exit
  -ntds NTDS            Path to .ntds file
  -nxc                  Scan $HOME/.nxc/logs/ntds for .ntds files
  -w WORDLIST WORDLIST2 [WORDLIST WORDLIST2 ...], --wordlists WORDLIST WORDLIST2 [WORDLIST WORDLIST2 ...]
                        Wordlists to use with hashcat
  -e, --enabled-only    Only show enabled accounts
  -nd, --no-domain      Don't display domain in usernames
  -csv                  Save output in CSV format
  ```

this command wants to get supplied with ntds file by user or netexec then does classic revealhashed operations.  

_ntds file should contain usernames and hashes. it should be not ntds.dit. example ntds dump can be obtained from repo._  

-ntds or -nxc switch is needed. -ntds switch is for a file you own with hashes. -nxc switch is for scanning ~/.nxc/logs/ntds directory then selecting .ntds file.  
-w (wordlist) switch is needed. one or more wordlists can be supplied.  
-e (enabled-only) switch is not needed but suggested. it's self explanatory; only shows enabled users.  
-nd (no-domain) switch hides domain names in usernames.  
-csv (csv) switch is self explanatory; saves output to csv instead txt.  

for example:  
`revealhashed reveal -ntds <ntds_file>.ntds -w wordlist1.txt -e -nd -csv`  
`revealhashed reveal -nxc -w wordlist1.txt -e -nd -csv`

## example outputs
![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp1.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp2.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp3.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp4.PNG)
