# cve_pull

cve_pull is a tool to pull Common Vulnerabilities and Exposures (CVE) from the National Vulnerability Database (NVD). 

## Install 
```
git clone https://github.com/ajread4/cve_pull.git
cd cve_pull
pip3 install -r requirements.txt
```
## Usage
```
$ python3 cve_pull.py -h
usage: cve_pull.py [-h] [-c  cve] [-f  cve_file] [-d]

cve_pull - a tool to pull information regarding a CVE or multiple CVEs from the National Vulnerability Database (NVD).

options:
  -h, --help            show this help message and exit
  -c  cve, --cve cve    specify the CVE #
  -f  cve_file, --file cve_file
                        specify a CSV with multiple CVE #s in a single column
  -d, --description     return the description of the CVE
```
### Example 
1. Return the CVSS for CVE-2020-0764. 
```
$ python3 cve_pull.py -c CVE-2020-0764
CVSS2 Score: 4.6 MEDIUM
CVSS3 Score: 7.8 HIGH
```
2. Return the CVSS and description of CVE-2021-45046. 
```
$ python3 cve_pull.py -c CVE-2021-45046 -d
CVSS2 Score: 5.1 MEDIUM
CVSS3 Score: 9.0 CRITICAL
Description: It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.
```
3. Return the CVSS for each CVE within an input file. 
```
$ python3 cve_pull.py -f /home/ajread/code/KEV_CVEs.csv
CVE: CVE-2004-2761
5.0 MEDIUM
No CVSSv3 Score
CVE: CVE-2012-1823
7.5 HIGH
No CVSSv3 Score
CVE: CVE-2013-0640
9.3 HIGH
No CVSSv3 Score
CVE: CVE-2013-0641
9.3 HIGH
No CVSSv3 Score
CVE: CVE-2013-1609
6.8 MEDIUM
No CVSSv3 Scores
```
## Author 
All code was written by me, AJ Read, with inspiration from [MachineThing's](https://github.com/MachineThing) [cve_lookup](https://github.com/MachineThing/cve_lookup/tree/development). 
- Twitter: [ajread3](https://twitter.com/ajread3)
- Github: [ajread4](https://github.com/ajread4)
- LinkedIn: [Austin Read](https://www.linkedin.com/in/austin-read-88953b189/)