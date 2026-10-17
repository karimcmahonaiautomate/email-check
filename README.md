# Email Finder & Validity Checker

### How to run it

To find an email, run: python3 emailcheck.py --helo [yourdomain.com] --from [you@yourdomain.com] find [“First Last" companydomain.com] --scan-site

To verify an email, run: python3 emailcheck.py  --helo [yourdomain.com] --from [you@yourdomain.com] verify [email address]

(Brackets are not used, just to show where information should be inserted)

### How it works

The script runs these layers for verification:
	1	Syntax: checks the address format.
	2	Flags: marks disposable domains (Mailinator and similar), role accounts (info@, sales@) and free providers (Gmail and similar).
	3	DNS MX lookup: checks whether the domain can receive mail at all.
	4	SMTP handshake: connects to the mail server and asks whether it would accept the address. No email is sent.
	5	Catch-all detection: probes a random fake address. If the server accepts it, the result is “risky” rather than “valid”.

You get a status (valid, invalid, risky or unknown) plus a 0–100 score.
And to find someone’s email:
It generates 15 common patterns (jane.doe@, jdoe@, janed@ and so on), ranked by how common they are, and tests each one. It stops at the first confirmed hit unless you pass --all. With --scan-site, it also scrapes the company’s public pages for existing emails to infer their format and tries that pattern first. If the domain is catch-all, it can’t confirm anything, so it just shows the ranked guesses.
