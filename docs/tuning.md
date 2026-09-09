# Rule tuning

The Core Rule Set catches attacks and, at first, some of your own application.
Tuning is how you separate them — and the reason this tool never blocks is so
you can do it against real traffic without an outage.

## The workflow

1. Run in detection for long enough to see normal traffic. A week covers most
   weekly patterns.
2. Open **Rule tuning**. Rules are ranked by volume; the noisiest are usually
   false positives, because real attacks are rarer than your own users.
3. For a suspect rule, open a matching request from **Traffic** and read the WAF
   tab: the rule, its message, and the data that matched. That tells you whether
   it caught your rich-text editor or an actual payload.
4. Mark it. **False positive** and **Real attack** both feed the queue, so the
   ranking reflects judgement rather than volume alone.
5. Exclude what is genuinely benign. The exclusion is stored, rendered as
   SecLang, and loaded by the proxy on its next poll.

## Exclusion forms

| Situation | Directive |
| --- | --- |
| The rule is wrong for this app everywhere | `SecRuleRemoveById 942100` |
| Only one parameter trips it | `SecRuleUpdateTargetById 942100 "!ARGS:comment"` |
| Only one path trips it | A rule with `ctl:ruleRemoveById=942100` scoped by URI prefix |
| One parameter on one path | A rule with `ctl:ruleRemoveTargetById` scoped by URI prefix |

Prefer the narrowest form that works. Removing a rule outright turns off that
detection for every request to the app.

Exclusions are per application. Rules that should apply everywhere belong in
`PROXY_RULES_DIR` instead.

## Marking a match

The buttons on a matched rule — **Our own traffic** and **Real attack** — record
a judgement and nothing else. They do not change detection, do not block, and do
not alter the rule. What they do is rank the tuning queue and tell whoever looks
next what you concluded.

## Choosing a threshold

The anomaly score accumulates across matching rules: critical adds 5, error 4,
warning 3, notice 2. The threshold decides what counts as an attack.

The simulator on the tuning page answers the only question that matters before
you enforce anything: at this threshold, over this window, how many recorded
requests would have been blocked — and which ones.

A workable sequence:

1. Start at the default threshold of 5 and read the count. If it is a meaningful
   fraction of your traffic, you have tuning left to do.
2. Tune until the blocked set contains only requests you are content to reject.
   Inspect them; the simulator's number is a starting point, not a verdict.
3. Raise the paranoia level one step and repeat. Higher levels catch more and
   demand more tuning.

## Paranoia levels

| Level | Character |
| --- | --- |
| 1 | Few false positives. The sensible default. |
| 2 | Catches more, needs real tuning. |
| 3 | Aggressive. Expect to exclude regularly. |
| 4 | Very aggressive. Appropriate only for narrow, well-understood applications. |

## Enforcing

Set the application's mode to **Reject** on the Applications page. Requests
whose score reaches the threshold get a 403 quoting a reference you can search
for; everything else is forwarded untouched.

The rule engine stays in detection mode either way. The decision is taken from
the same anomaly score the simulator reports, so enforcing does what the
simulation said it would.

Mode is per application, so one can enforce while another still only records.
