Most teams think a remediation script makes their image STIG-compliant.

The data says otherwise.

Two Dockerfiles, same mandate (DISA STIG, 300+ rules):
   Image A:  ubuntu:22.04 + 354-line remediation script  (retrofit)
   Image B:  cleanstart/glibc                             (hardened)

Both pass a compliance review on paper. Both run as non-root.
Same Docker host. Same build toolchain.

Actual results after running both builds:

                     Retrofit        CleanStart
Image size           145 MB          44.9 MB
Packages             126             0
Shell present        /usr/bin/bash   none
Package manager      apt + dpkg      none
Remediation script   354 lines       none
Build time           83s             2s

Same mandate. Same app. The only difference is the base image.

Why does retrofit NOT solve the problem?

Because a STIG rule doesn't care how many lines you wrote.
It cares whether the binary is present.

After 354 lines of remediation, the retrofit image still ships:
   wget, curl, tar           (STIG flags these — can't remove, breaks builds)
   apt, dpkg                 (STIG flags these — can't remove, breaks the OS)
   /usr/bin/bash             (STIG flags this — wired into Ubuntu core)
   ~20 setuid binaries       (mount, su, sudo, ping — pruning breaks the image)
   perl, python3             (pulled in transitively, can't avoid)

Every one of those is a STIG finding your script wrote around, not fixed.
And every quarter, when DISA ships a new benchmark version, someone rewrites the script again.

Retrofit protects against ONE thing:
the auditor seeing a stock Ubuntu image.

It does NOT protect against:
- Structural STIG findings that can't be remediated without breaking the image
- CVEs in the 126 packages that are still present
- Living-off-the-land attacks (bash, curl, gcc all still there)
- Quarterly benchmark drift — 300+ rules, your team's maintenance burden forever
- The engineer who owns the script leaving

The real fix isn't writing more remediation.
It's changing the FROM.

Full Dockerfiles, the complete 354-line script, and a single run.sh that reproduces every number above — open source:
github.com/cleanstart-dev/cleanstart-use-cases/tree/main/stig-by-design-vs-retrofit-v3

Run it yourself. 5 minutes. One command.

#ContainerSecurity #STIG #DevSecOps #DISA #CleanStart #Compliance #Docker
