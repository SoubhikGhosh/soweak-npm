# Angular example

Two files, drop them into any Angular 17+ project.

* `soweak.service.ts` — Angular `@Injectable` service that builds a soweak
  Pipeline once and exposes `scanInput`, `scanOutput`, and `secureFetch`.
* `chat.component.ts` — standalone component that uses the service to guard
  a chat box.

## Install

```bash
npm install soweak
```

## What stays Node-only

`JsonLinesAuditLog`, `FileCounterStore`, `FileWindowStore`, and `loadPolicy`
all need `fs` and won't run in the browser. Use `CallbackAuditLog` for the
audit sink and `buildPolicy` (passing parsed JSON) for declarative
policies.
