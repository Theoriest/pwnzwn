# Masterclass: Assume-Role, externalId & Session-Tag Abuse, Spotting It in the Wild, From Zero

**Companion to:** `stageworks-assume-role-writeup.md`

Stageworks models **cloud identity federation** (AWS STS `AssumeRole`). The bug, letting a caller assert their own authorization attributes (session tags) plus a leaked trust secret (externalId), is one of the most common and highest-impact classes in real cloud environments. This guide teaches, from zero: what assume-role / externalId / session tags are, exactly how this goes wrong, and, the part you asked for, **how to identify these issues in the wild** (in IAM policies, in code, and black-box against an API).

---

## How to read this

- **Part 0**, roles, assume-role, externalId, and session tags.
- **Part 1**, the one idea: never authorize on attributes the caller controls.
- **Part 2**, the two bugs here (leaked externalId + forged tag).
- **Part 3**, **identifying it in the wild** (IAM review, code review, black-box).
- **Part 4**, the fixes.
- **Glossary**.

---

# PART 0, The Building Blocks

**Roles & assume-role.** Instead of long-lived credentials, modern systems let a principal *temporarily assume a role* to get scoped, short-lived access. AWS's call is `sts:AssumeRole`: you name a role, prove you're allowed, and get back temporary credentials (here, a `token`). The role's **trust policy** says *who* may assume it and *under what conditions*.

**externalId.** When a **third party** (e.g. a SaaS vendor) assumes a role in *your* account, there's a classic risk: an attacker tricks the vendor into assuming *your* role on the attacker's behalf, the **confused deputy**. AWS's defence is **`sts:ExternalId`**: a shared secret you give the vendor; your trust policy requires it. It's not a password you brute-force, it's an agreed value that must match. **If it leaks, the protection is gone.**

**Session tags.** When assuming a role you can attach **session tags** (key/value attributes) that ride along with the temporary credentials. Resource policies can then make decisions on them (`aws:PrincipalTag/department == finance`). Powerful, and dangerous if the *assuming* party gets to choose authorization-bearing tags.

On Stageworks: `policy.json` is the trust+resource policy; `POST /api/assume` is `AssumeRole`; the `token` is the session; `tagSession:true` means "apply the caller's tags to the session."

---

# PART 1, The One Idea

> **Never make an authorization decision based on an attribute the caller can set.**

Two attributes decided access here, and the caller controlled both:
- the **externalId** (meant to be a secret, but it leaked, so the caller "has" it), and
- the **session tag** `department=finance` (meant to describe a trusted identity, but the caller asserts it in the request).

When the thing that grants access is the thing the attacker supplies, there is no access control.

---

# PART 2, The Two Bugs, Precisely

### 2.1 Leaked externalId (the trust gate falls)
`deployment.log` contained `externalId=d4a868d5e1dbf4bf89c6c520`. The trust check for `lighting` just compares the submitted externalId to this value. Because it's in a readable artifact, anyone can satisfy the trust. (Real-world equivalent: externalId in CI logs, Terraform state, a committed `.tfvars`, a vendor onboarding doc.)

### 2.2 Forged session tag (the resource gate falls)
The finance object requires `sessionTag/department == "finance"`. With `tagSession:true`, the server takes `tags` straight from the assume **request body** and stamps them on the session, so the caller writes their own `department=finance`. The `lighting` role has no business producing a finance-tagged session, but nothing stops it.

**Chained:** leaked secret → pass trust → self-asserted tag → pass resource condition → read the object. Each gate individually "works"; together they're bypassed because both inputs are attacker-controlled.

---

# PART 3, Identifying This in the Wild

This is the transferable skill. Three lenses:

### 3.1 Reviewing IAM / trust policies
Red flags in an AWS (or AWS-like) setup:
- **A role trusting an external account/vendor with no `sts:ExternalId` condition**, confused-deputy exposure. (And if an externalId *is* used, check it isn't committed/logged.)
- **`"Action": "sts:TagSession"` granted to the assuming principal**, combined with **resource/permission policies that condition on `aws:PrincipalTag/...`**. That's "the caller sets a tag that then grants access." Look for `aws:PrincipalTag`/`aws:RequestTag` in `Condition` blocks whose tag the *assuming* side controls.
- **Trust policies with `"sts:ExternalId": "*"`** or wildcarded conditions.
- **No `aws:TagKeys` / transitive-tag constraints** limiting which tags a session may carry.

Commands/tools: read `aws iam get-role --role-name X` (trust policy), `get-role-policy`/`list-attached-role-policies`, and run **IAM Access Analyzer**, `prowler`, `ScoutSuite`, or `cloudsplaining` to flag over-broad trust and tag conditions.

### 3.2 Reviewing code
In an app that federates or mints sessions, grep for the smell:
- Session/JWT claims or tags **taken from the request** and later used in `if session.tags[...] == ...` authorization. (e.g. `assume(role, tags=request.json["tags"])` then `authorize(session.tags)`.)
- A **shared secret compared from config** that also appears in logs (`log.info(f"...externalId={external_id}")`, exactly this box).
- Trust/role checks that validate `role` and `externalId` but then **trust everything else in the body**.

### 3.3 Black-box against an API (what we did)
1. **Enumerate the identity flow:** find `assume`/`token`/`session`/`federate` endpoints and what they accept (`role`, `external_id`, `tags`, `scope`, `duration`).
2. **Find what gates the prize:** some object/endpoint has a *condition* (a tag, a role, an account). Read any policy/manifest file (`policy.json`, `.well-known`, config downloads).
3. **Ask: who sets that gating attribute?** If it's a **tag/claim you can pass at assume/login time**, set it to the required value, that's the forge.
4. **Find the trust secret:** externalId/keys often leak in **logs, docs, downloads, JS, or are derivable** (hash of a public value, test `hash(role)[:n]` like Night Bus).
5. **Chain:** satisfy trust (leaked/forged secret) → self-assert the gating tag → hit the protected resource.

The habit: **map every attribute to "who controls it," then check whether an attacker-controlled one grants access.**

---

# PART 4, The Fixes

- **Protect the externalId:** treat it as a secret, out of logs (`CWE-532`), artifacts, and client-reachable files; rotate on exposure; scope the trust policy narrowly (specific principal + exact externalId).
- **Don't authorize on caller-set tags:** session tags used in conditions must be **set by the trusted side** (the identity provider / role definition), or constrained via trust-policy conditions (`aws:TagKeys`, allowed values). Never copy `request.tags` into an authorization-bearing session tag.
- **Least privilege:** the low role (`lighting`) must not be able to mint a session that satisfies a *different* department's condition.
- **Separate authentication from authorization:** proving you may assume a role ≠ being allowed to read finance data; check the *resolved, trusted* attributes at the resource.

---

# Glossary

- **AssumeRole / STS**, getting temporary, scoped credentials by assuming a role.
- **Trust policy**, defines who may assume a role and under what conditions.
- **externalId (`sts:ExternalId`)**, a shared secret preventing the **confused-deputy** attack when a third party assumes your role.
- **Confused deputy**, tricking a privileged intermediary into acting for the attacker.
- **Session tags**, attributes attached to assumed-role credentials; may be used in authorization conditions (`aws:PrincipalTag`).
- **`tagSession`**, (here) a flag making caller-supplied tags become session tags, the forge vector.
- **CWE-863**, incorrect authorization; **CWE-532**, info exposure through logs.

---

# Where to Go Next

- Read the **AWS docs on ExternalId (confused deputy)** and **session tags / `aws:PrincipalTag`** conditions, then review a real trust policy with that lens.
- Run **cloudsplaining / prowler / IAM Access Analyzer** on a test account and read what they flag about cross-account trust and tag conditions.
- Practise the black-box habit: for any login/assume/federation API, **tabulate each field by who controls it**, and try self-asserting the attribute that gates the prize.

The transferable idea: **authentication proves who you are; authorization must rely on attributes you *can't* forge.** The moment a role, a tag, or an externalId that grants access is something the caller supplies (or can read), the gate is already open.
