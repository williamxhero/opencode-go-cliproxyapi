# Task 8 (opencode-go plugin repo): a credential-writing route, so OpenCode Go can be added from a panel form

Repo (work here): `D:\WILL\AGENT\CPA\opencode-go-cliproxyapi` (this is the user's fork; `origin` = `massiveits/opencode-go-cliproxyapi`, remote **`fork`** = `https://github.com/williamxhero/opencode-go-cliproxyapi-ex.git`). Push to **`fork`**.
Branch: `claude/credential-route`.

## Why

The panel is getting a single "添加计划凭证" page that hosts one form per plan plugin: **Base URL + API Key + Alias/名称 → 添加 → 创建凭证**. The Qwen plugin already implements its half; OpenCode Go must offer the same route, otherwise the OpenCode module of that page cannot work. Today an OpenCode Go credential can only come from the plugin's configured `api-keys`.

## Template (our own code, MIT-compatible — mirror it)

`D:\WILL\AGENT\CPA\qwen-cliproxyapi\internal\plugin\credentials.go` (+ `auth.go`, `management.go`, `executor.go` and their tests). Copy the shape, not the names.

## Deliverable

1. **`POST /v0/management/plugins/opencode-go-cliproxyapi/credentials`**

       body: {"base_url": "https://opencode.ai/zen/go/v1", "api_key": "oc_sk_...", "name": "Personal"}
       ok:   {"ok": true, "id": "opencode-go-key-<hash>", "label": "Personal"}
       err:  {"error": "<short reason>"} with an honest 4xx/5xx

   * Validate `base_url` (http/https, host present, no userinfo/query/fragment — same rules as the existing `base-url` config; honour the plugin's `allow-http` switch) and a non-empty `api_key`; `name` optional (default a sensible label).
   * Reject a duplicate credential (same key + base URL) with a clear 409-style error.
   * Persist through the host auth API exactly the way the plugin already materialises configured keys (no hand-rolled file writes with a different schema); provider stays `opencode-go`; the label is the given name.
   * Never echo the key; never log it; a failed write leaves no partial credential.
2. **Per-credential base URL**: a credential created this way carries its own `base_url`; execution must prefer it and fall back to the plugin config's `base-url`. Cover both paths with a test that asserts the effective upstream URL.
3. **Registration**: add the route to the plugin's `management.register` route list (keep the existing quota-usage route and existing behaviour). Do **not** add a new panel menu/resource entry, and if the plugin currently advertises a resource menu that the panel is about to replace, leave it untouched — the panel handles the nav.
4. Include the new credential in whatever the plugin already reports for quota/usage if that logic enumerates credentials (do not break its existing `key_id` contract).

## Tests / quality

`CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test ./... -cover -count=1` green; extend the existing suite (don't regress it): happy path, bad/missing base_url, empty key, duplicate, unknown fields ignored, no secret in response/log text, credential file content/provider/label, base-URL precedence, registration envelope contains the new route. Report named test count + coverage.

## Build & verify (real evidence)

    export PATH="/d/WILL/AGENT/agent/.tmp/winlibs-cpa-build/mingw64/bin:$PATH"
    CGO_ENABLED=1 go build -buildmode=c-shared -o plugins/windows/amd64/opencode-go-cliproxyapi.dll .

Then an **isolated core on 8399** (copy the core exe into a scratch dir outside the repo, own auth-dir/config, `plugins.dir` = this repo's `plugins`, dummy keys only): paste verbatim the `/v0/management/plugins` entry, `POST .../credentials` with a dummy key, the resulting `/v0/management/auth-files` entry, and a duplicate submission's response. Do not touch the live core on 8317 (`D:\APP\EasyCLIProxyAPI-...`): no config edits, no restart, no DLL copy — Hermes deploys. Stop the scratch instance and delete the scratch dir.

## Constraints

* Never touch `D:\WILL\AGENT\CPA\qwen-cliproxyapi` or the panel repo.
* No secrets in the repo/tests/logs.
* Honest reporting: unverified ⇒ say unverified.

## FINAL REPORT (exact shape)

    VERDICT: PASS | FAIL | PARTIAL
    BRANCH: <branch + pushed to fork?>
    COMMITS: <sha list>
    FILES CHANGED: <paths>
    TESTS: <command> -> <result>, named tests <n>, coverage <per package>
    ARTIFACT: dll <path> <size>
    E2E (8399): plugins=<verbatim>; credentials POST=<verbatim>; auth-files=<verbatim>; duplicate=<verbatim>
    BASE URL PRECEDENCE: <how verified>
    LIVE 8317: untouched? <yes/no>
    KNOWN LIMITS: <bullets>
    REMAINING: <what Hermes must do>
