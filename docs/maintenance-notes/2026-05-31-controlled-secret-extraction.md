# Controlled Secret Extraction

## Trigger

The workflow still contained language that could be read as a ban on plaintext secret dumping. In real forensic work, credentials, cookies, tokens, keys, password stores, and environment files may unlock additional evidence, identify further victims, or prove access and intent.

## Change

- Reframed secret handling as an authorized evidence lane when it is inside case authority and scope.
- Allowed explicit secret extraction or dumping to approved controlled case-output files.
- Kept public repository content, ordinary prompts, terminal previews, and report prose redacted unless disclosure is specifically required.
- Added provider/model routing guidance: if the active AI interface, provider policy, system instruction, or enterprise rule does not allow plaintext secret handling, move that lane to approved local tools, offline execution, or a local model and record the change.
- Updated script authoring and review rules so generated scripts can include explicit secret-extraction mode with controlled outputs and validation.

## Guardrails preserved

- legal and policy scope discipline
- preservation-first handling
- controlled output roots
- mandatory subagent loop
- publication redaction
- report disclosure of handling decisions and limitations
