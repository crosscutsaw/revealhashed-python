
## about revealhashed-python v0.3.0
revealhashed is a streamlined utility to correlate ntds usernames, nt hashes, and cracked passwords in one view while cutting out time-consuming manual tasks.  

## dependencies  
hashcat  
impacket or python3-impacket  
neo4j  

## how to install
from pypi:  
`pipx install revealhashed`  

from github:  
`pipx install git+https://github.com/crosscutsaw/revealhashed-python`  

`git clone https://github.com/crosscutsaw/revealhashed-python; pipx install revealhashed-python/`

## how to use
```
revealhashed v0.3.0

usage: revealhashed [-h] [-r] {dump,reveal} ...

positional arguments:
  {dump,reveal}
    dump         Dump NTDS from a DC and reveal credentials.
    reveal       Reveal credentials from an existing NTDS dump.

options:
  -h, --help     show this help message and exit
  -r, --reset    Delete old session data in ~/.revealhashed
```
### revealhashed -r
just execute `revealhashed -r` to remove contents of ~/.revealhashed

### revealhashed dump
```
revealhashed v0.3.0

usage: revealhashed dump [-h] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey HEXKEY] [-dc-ip IP] [-codec CODEC] [-e] [-nd] [-csv] [-bh] [--dburi DBURI] [--dbuser DBUSER] [--dbpassword DBPASSWORD]
                         [-m {ntdsutil,drsuapi,vss}] [-history] [-just-dc-user USER] -w WORDLIST [WORDLIST ...]
                         target

positional arguments:
  target                [[domain/]username[:password]@]<host>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output on
  -hashes LMHASH:NTHASH
                        NTLM hashes to authenticate with
  -no-pass              Don't prompt for a password
  -k                    Use Kerberos authentication
  -aesKey HEXKEY        AES key for Kerberos authentication
  -dc-ip IP             IP address of the domain controller
  -codec CODEC          Encoding used for output decoding
  -e, --enabled-only    Only show enabled accounts
  -nd, --no-domain      Strip the domain from displayed usernames (output only)
  -csv                  Also save output as CSV
  -bh                   Mark cracked users as owned in BloodHound
  --dburi DBURI         BloodHound Neo4j URI (default: bolt://localhost:7687)
  --dbuser DBUSER       BloodHound Neo4j username (default: neo4j)
  --dbpassword DBPASSWORD
                        BloodHound Neo4j password (default: 1234)
  -m, --method {ntdsutil,drsuapi,vss}
                        NTDS dump method (default: ntdsutil)
  -history              Dump password history
  -just-dc-user USER    Only extract this user's data
  -w, --wordlists WORDLIST [WORDLIST ...]
                        Wordlists to use with hashcat
```

this command executes [zblurx's ntdsutil.py](https://github.com/zblurx/ntdsutil.py) to dump ntds safely as default. if it doesn't work, drsuapi or vss methods can be used. after dump it does classic revealhashed operations.  

-w (wordlist) switch is needed. one or more wordlists can be supplied.    
-e (enabled-only) switch is suggested. it's only shows enabled users.  
-nd (no-domain) switch strips domain names from usernames.  
-bh (bloodhound) switch marks cracked users as owned in bloodhound. if used, `--dburi`, `--dbuser` and `--dbpassword` are also needed to connect neo4j database. it supports both legacy and ce.  
-csv (csv) switch saves output to csv, together with txt.  

for example:  
`revealhashed dump '<domain>/<username>:<password>'@<dc_ip> -w wordlist1.txt wordlist2.txt -e -nd -csv -bh --dburi bolt://localhost:7687 --dbuser neo4j --dbpassword 1234`

### revealhashed reveal
```
revealhashed v0.3.0

usage: revealhashed reveal [-h] [-e] [-nd] [-csv] [-bh] [--dburi DBURI] [--dbuser DBUSER] [--dbpassword DBPASSWORD] [-ntds NTDS] [-nxc] [-w WORDLIST [WORDLIST ...]]

options:
  -h, --help            show this help message and exit
  -e, --enabled-only    Only show enabled accounts
  -nd, --no-domain      Strip the domain from displayed usernames (output only)
  -csv                  Also save output as CSV
  -bh                   Mark cracked users as owned in BloodHound
  --dburi DBURI         BloodHound Neo4j URI (default: bolt://localhost:7687)
  --dbuser DBUSER       BloodHound Neo4j username (default: neo4j)
  --dbpassword DBPASSWORD
                        BloodHound Neo4j password (default: 1234)
  -ntds NTDS            Path to a secretsdump .ntds file
  -nxc                  Pick a .ntds file from ~/.nxc/logs/ntds
  -w, --wordlists WORDLIST [WORDLIST ...]
                        Wordlists to use with hashcat
```

this command wants to get supplied with ntds file by user or netexec then does classic revealhashed operations.  

**_ntds file should contain usernames and hashes. it should be not ntds.dit. example ntds dump can be obtained from repo._**  

-ntds or -nxc switch is needed. -ntds switch is for a file you own with hashes. -nxc switch is for scanning ~/.nxc/logs/ntds directory then selecting an ntds file.  
-w (wordlist) switch is needed. one or more wordlists can be supplied.  
-e (enabled-only) switch is suggested. it's only shows enabled users.  
-nd (no-domain) switch strips domain names from usernames.  
-bh (bloodhound) switch marks cracked users as owned in bloodhound. if used, `--dburi`, `--dbuser` and `--dbpassword` are also needed to connect neo4j database. it supports both legacy and ce.  
-csv (csv) switch saves output to csv, together with txt.  

for example:  
`revealhashed reveal -ntds <ntds_file>.ntds -w wordlist1.txt -e -nd -csv`  
`revealhashed reveal -nxc -w wordlist1.txt -e -nd -csv`

## example outputs
![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp1.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp2.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp3.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp4.PNG)

![](https://raw.githubusercontent.com/crosscutsaw/revealhashed-python/main/rp5.PNG)
