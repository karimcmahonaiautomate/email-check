{\rtf1\ansi\ansicpg1252\cocoartf2822
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;\f1\froman\fcharset0 Times-Roman;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;}
{\*\expandedcolortbl;;\cssrgb\c0\c0\c0;}
{\*\listtable{\list\listtemplateid1\listhybrid{\listlevel\levelnfc0\levelnfcn0\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{decimal\}}{\leveltext\leveltemplateid1\'01\'00;}{\levelnumbers\'01;}\fi-360\li720\lin720 }{\listname ;}\listid1}}
{\*\listoverridetable{\listoverride\listid1\listoverridecount0\ls1}}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 # Email Finder & Validity Checker\
\
### How to run it\
\
To find an email, run: \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 python3 emailcheck.py --helo [yourdomain.com] --from [you@yourdomain.com] find [\'93First Last" companydomain.com] --scan-site\
\
To verify an email, run: python3 emailcheck.py  --helo [yourdomain.com] --from [you@yourdomain.com] verify [email address]\
\
(Brackets are not used, just to show where information should be inserted)\
\
### How it works\
\
\pard\pardeftab720\sa240\partightenfactor0
\cf0 \strokec2 The script runs these layers for verification:\
\pard\tx220\tx720\pardeftab720\li720\fi-720\partightenfactor0
\ls1\ilvl0\cf0 \kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	1	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Syntax: checks the address format.\
\ls1\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	2	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Flags: marks disposable domains (Mailinator and similar), role accounts (info@, sales@) and free providers (Gmail and similar).\
\ls1\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	3	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 DNS MX lookup: checks whether the domain can receive mail at all.\
\ls1\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	4	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 SMTP handshake: connects to the mail server and asks whether it would accept the address. No email is sent.\
\ls1\ilvl0\kerning1\expnd0\expndtw0 \outl0\strokewidth0 {\listtext	5	}\expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 Catch-all detection: probes a random fake address. If the server accepts it, the result is \'93risky\'94 rather than \'93valid\'94.\
\pard\tx720\pardeftab720\partightenfactor0
\cf0 \
\pard\pardeftab720\sa240\partightenfactor0
\cf0 You get a status (valid, invalid, risky or unknown) plus a 0\'96100 score.\
And to find someone\'92s email:\
\pard\pardeftab720\partightenfactor0
\cf0 It generates 15 common patterns (\strokec2 jane.doe@\strokec2 , \strokec2 jdoe@\strokec2 , \strokec2 janed@\strokec2  and so on), ranked by how common they are, and tests each one. It stops at the first confirmed hit unless you pass \strokec2 --all\strokec2 . With \strokec2 --scan-site\strokec2 , it also scrapes the company\'92s public pages for existing emails to infer their format and tries that pattern first. If the domain is catch-all, it can\'92t confirm anything, so it just shows the ranked guesses.\
\pard\pardeftab720\sa240\partightenfactor0

\f1 \cf0 \
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0 \cf0 \strokec2 \
\
}