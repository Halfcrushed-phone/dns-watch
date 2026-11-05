# DNS watch (phone-only)

**Got an email or notification saying "Run failed: WPM DNS ALARM"?** Read
[When it buzzes](#when-it-buzzes) below. The short version: tap **View workflow run** in
the email; the page it opens says what happened and exactly what to do, on your phone.

## When it buzzes

The run page says what kind it is, under "What this alarm means", with the steps to
take: a **fire drill** (every 15 January, or one you started), a **real** alarm, or a
problem with the watcher itself.

- **Changes logged.** Each `CHANGE` line is one write to Cloudflare. If you approved
  that work in the day or two before, and every line is it, nothing to do. Otherwise, on
  the phone: delete the **WPM DNS edit** key at https://dash.cloudflare.com/profile/api-tokens
  (the website and email keep working), and if any line is unfamiliar, change the
  Cloudflare password and end other sessions.
- **Could not read the change log.** NOT an all-clear. Usually the watcher's key
  expired: renew it (setup steps 3 and 4). If the key was deleted and you didn't delete
  it, treat it as a break-in, as above.
- **Registration changed.** Check the domains at GoDaddy now: nameservers must be the
  "expected" ones on the run log's NS DRIFT lines (no such line: they are fine), and
  DNSSEC must be off (a "DS present" line means it is on). (A
  "could not run" or "did not finish" note is not a hijack sign.)
- **Could not keep its schedule switched on.** Not a DNS problem: open this
  repository's **Actions** tab, tap the workflow, and tap **Enable workflow** if it says
  it is disabled.

Logs here never show record contents. To see what a record was set to, a session on the
PC can read the firm repo's own run, but do the phone steps first: the PC is what this
watches.

**Fire drills.** Every 15 January (UTC) the run fails on purpose, so the alarm stays
familiar and you know it still reaches the phone, this account's Gmail and the work
copy. To rehearse any time: **Actions → the workflow → Run workflow**, tick **drill**.
To prove a *scheduled* alarm reaches you (for example after changing this repository),
set a repository variable **DRILL_DATE** to tomorrow's date (`YYYY-MM-DD`, UTC) under
**Settings → Secrets and variables → Actions → Variables**; delete it afterwards.

**Never change the line `cron: "23 3 * * *"`** in the workflow, and never merge a change
from someone else that does: GitHub sends scheduled alarms to whoever last changed that
line.

A daily check of the firm's two domains that nothing on the firm's PC can switch off.

**Why it exists.** A standing key on the firm's PC can change the domains' DNS. The
firm repo's own daily checks are watched from that same PC, so a session or intruder
with the PC's credentials could change a record and silence the alarm. This copy runs
under a GitHub account that is signed in only on the operator's phone, with its own
read-only Cloudflare key that never touches the PC. When it finds a change, or cannot
read, the run fails and the GitHub app on the phone shows it.

**What it checks.** Every write Cloudflare logged to either zone since its last
successful read (a record added and removed between two checks still shows), any new or
changed Cloudflare API key or account member, and that both domains are still delegated to the firm's
Cloudflare nameservers at the .com and .ca registries, with no DS record.

**Who watches the watcher.** A run that fails buzzes the phone. A run that never starts
cannot. GitHub pauses schedules in a public repository after 60 days without activity;
each run switches its own schedule back on, which is meant to restart that clock (not
yet proven). The backstop is the firm repo's daily job: it reads this repository's
public run history and goes red if no run has started for two days. If that happens,
open this repository's Actions tab on the phone and tap **Enable workflow**.

**Never** sign in to this account, or make its key, on the firm's PC — that would put
it back within reach of the thing it watches. If the account has to be recovered, do it
from the phone.

## Setting it up (phone only, about 15 minutes, once)

1. Create a new GitHub account (it is the firm's one "machine account" under GitHub's
   terms) with an email address the PC cannot read: not the work mailbox and not any
   Gmail the PC is signed in to (a new address made on the phone works). Turn on
   two-factor sign-in with an authenticator app or passkey on the phone, and save the
   recovery codes somewhere that is not the PC.
2. Open the template link the setup session gives you, tap **Use this template** ->
   **Create a new repository**, owner = the new account, visibility **Public** (so the
   firm repo can see whether it is still running). Its run logs are public: they show
   when a change was made and the record's type and name, never the record's content
   or the name of the key that made it.
3. Open the Cloudflare link the setup session gives you, sign in, check the summary
   reads *Account Settings: Read* on the firm account, tap **Create Token**, copy it.
4. In the new repository: **Settings -> Secrets and variables -> Actions -> New
   repository secret**, name `CLOUDFLARE_AUDIT_READ_TOKEN`, paste, **Add secret**.
5. Install the GitHub app, sign in with the new account, and turn on push
   notifications for **Actions: failed workflows**.
6. For a copy at work: in this account's mailbox, add a filter that forwards only
   GitHub's alarm emails (from `notifications@github.com`, subject containing
   "Run failed") to the work address. Forward nothing else: the PC can read the work
   mailbox, and this account's sign-in and recovery emails must never reach it.

Then the setup session points the firm repo at this repository (so it notices if the
watcher stops), makes one harmless test record (shown to you first) and removes it. The
first run reads everything since 28 October 2026, so it buzzes whether or not it saw
the test: the session tells you the test record's name, and the test has worked only if
a `CHANGE` line names it (adding and removing it can make two lines). A record made less than 6 hours before a run is read by the
run after.
