"""P16: concrete security questions and interpretation criteria for manual testing.

These are advisory methodology statements, not vulnerability determinations.
"""
EXPLANATIONS = {
'TC-IN-001': ('Mismatch between supplied installer hash/version and the authorized delivery record, or unexplained provenance.', 'A substituted or untrusted installer enters the approved distribution workflow.', 'Metadata differences without a trusted comparison baseline or demonstrated security effect.'),
'TC-TG-001': ('Executable hash, provenance, signing and scope compared with the authorized portable build.', 'Untrusted or altered portable components are accepted as the intended application.', 'Unsigned portable programs when signing is not required, or unexplained adjacent files outside scope.'),
'TC-SG-001': ('Unexpected signer, failed Authenticode verification, disallowed certificate, or inconsistent signed binaries.', 'A security-sensitive executable is accepted despite violating an enforceable signing or trust requirement.', 'Missing signatures alone where no signing trust policy or impact has been established.'),
'TC-MS-001': ('Elevated MSI custom actions referencing user-modifiable paths, files, arguments, or properties.', 'A lower-privileged actor can influence code or arguments executed with installation privilege.', 'An elevated custom action without demonstrable attacker control of its inputs.'),
'TC-PE-001': ('Missing or inconsistent ASLR/NX/CFG metadata, including DUMPBIN CF Instrumented and FID table fields.', 'A relevant exploit mitigation is absent in a security-sensitive binary and its impact is defensible in context.', 'Missing PE header flags or a DUMPBIN REVIEW_REQUIRED label alone; mitigations are defense in depth.'),
'TC-CF-001': ('A credible non-placeholder active credential, token or private key; identify exposure and intended consumer.', 'An unauthorized principal can obtain or misuse a genuinely sensitive reusable value.', 'Framework strings, public certificates, sample/test keys, invalid or unused values, and regex matches alone.'),
'TC-FS-001': ('Newly installed sensitive executables, libraries, configuration files and directories writable by unintended principals.', 'A lower-trust user can alter a file consumed by a more privileged application component.', 'Writable user-specific data that is not trusted by higher-privilege functionality.'),
'TC-RG-001': ('New registry keys controlling privileged execution, trusted paths or security settings with broad effective write access.', 'A lower-trust actor can change a value subsequently trusted across a privilege boundary.', 'Registry changes or broad read access without a sensitive write/influence path.'),
'TC-SV-001': ('Privileged service executable, DLL, script, config or service setting writable by a standard user.', 'A lower-privileged identity can modify an artifact actually consumed by the privileged service.', 'Unquoted paths or writable directories without a feasible execution/consumption scenario.'),
'TC-TS-001': ('High-privilege task action, trigger, executable and arguments controllable by lower-trust principals.', 'A lower-privileged actor influences a scheduled task that executes at higher privilege.', 'A privileged task that cannot be influenced by the tested user.'),
'TC-PB-001': ('A concrete user-to-admin/SYSTEM data or execution boundary in discovered application behavior.', 'A lower-trust user alters inputs executed or trusted by a higher-privilege component.', 'Administrator-only observations not independently reproducible as a standard user.'),
'TC-DR-001': ('Installed driver, interface exposure, service permissions, trust/signature and unexpected device operations.', 'An untrusted caller can perform a security-sensitive driver operation or load an untrusted driver.', 'Driver presence, legacy build age or a permissive name without demonstrated access and effect.'),
'TC-PM-001': ('File, registry, process and image-load events associated with a repeatable application action.', 'Observed operations reveal an unauthorized cross-boundary write, execution or trust decision.', 'Single Procmon events without context, repeatability or verified security impact.'),
'TC-DL-001': ('Attempted DLL loads from attacker-writable directories and actual module resolution order.', 'An attacker-controlled DLL is loaded by a higher-trust process in an authorized controlled reproduction.', 'NAME NOT FOUND events or directory writability without an achievable DLL-load path.'),
'TC-AR-001': ('Managed assemblies, relevant code paths and calls crossing into privileged, native or security-sensitive operations.', 'Untrusted input reaches a sensitive operation without sufficient validation or authorization.', 'Decompiled strings or dangerous-looking API names without a reachable misuse path.'),
'TC-AR-002': ('Observed child process, command line, caller token and source of executable/arguments.', 'Untrusted user input influences command invocation across a security boundary.', 'Expected helper launches without controllable executable, arguments or effect.'),
'TC-AR-003': ('Loaded modules, signer/path mismatches and modules from lower-trust locations.', 'An untrusted module can be loaded into a sensitive target process under the tested conditions.', 'Unsigned or unexpected modules without effective attacker control or security impact.'),
'TC-AR-004': ('Reachable sensitive managed/native methods, caller checks, input validation and runtime effects.', 'A controlled caller bypasses an intended privilege or authorization boundary through the instrumented path.', 'A suspicious code pattern without reachability, real authorization bypass or impact.'),
'TC-MC-001': ('A reproducible crash or memory-safety signal attributable to an authorized attacker-controlled input.', 'Evidence supports a real memory-safety violation with a plausible security consequence.', 'A single crash, abnormal exit, or debugger warning without root-cause evidence.'),
'TC-NW-001': ('Live target-owned listening sockets, bind scope, owning process and purpose.', 'A target-owned network service is unintentionally reachable across a meaningful trust boundary.', 'A listener on its own; loopback or public binds are context, not automatic findings.'),
'TC-NW-002': ('Local service routes/commands that perform sensitive actions and their caller authentication/authorization.', 'A low-trust local caller invokes a restricted operation through a localhost endpoint.', 'HTTP 200 responses or unauthenticated public/status endpoints without restricted capability.'),
'TC-UP-001': ('Updater executable, trust chain, privileged transition, package source and controllable inputs.', 'An untrusted actor supplies update data or code that a privileged updater subsequently accepts.', 'An updater running elevated without a demonstrated controllable trust input.'),
'TC-UP-002': ('Actual update package verification, signature/hash enforcement and modified-package rejection.', 'Tampered or unauthorized update payloads are installed contrary to the intended trust policy.', 'A missing standalone signature file when an alternate authenticated integrity mechanism exists.'),
'TC-UP-003': ('Writable staging paths or temp payloads consumed by a privileged updater.', 'A lower-privileged actor changes staged update content before privileged consumption.', 'A writable temporary directory with no race, trust or consumption path.'),
'TC-UP-004': ('Update endpoint TLS validation, redirect behavior, content trust and exposure of update secrets.', 'An untrusted endpoint or network actor can cause acceptance of unauthorized update content.', 'Plaintext metadata requests without sensitive content or an update authenticity bypass.'),
'TC-UP-005': ('Authorized downgrade behavior versus intended version/rollback enforcement.', 'An untrusted actor can force a security-relevant disallowed downgrade.', 'An expected vendor-supported rollback with no breached security requirement.'),
'TC-IP-001': ('Named pipes, COM/RPC, local APIs and owning process with caller privileges and sensitive operations.', 'A lower-trust client invokes a restricted action due to missing endpoint authorization.', 'IPC endpoint discovery or connection success alone.'),
'TC-IP-002': ('Effective pipe ACL, owning privileged process, application protocol and caller authorization checks.', 'A standard user performs a higher-privileged operation through a pipe without intended authorization.', 'Broad pipe access alone when server-side authorization prevents sensitive operations.'),
'TC-LS-001': ('Real sensitive state, its application consumer, and effective read/write access across user contexts.', 'An unauthorized local identity reads or changes security-sensitive state.', 'Keywords, schemas or ordinary application data without actual sensitivity and access impact.'),
}


def enrich_test_cases(cases):
    for case in cases:
        if case['id'] not in EXPLANATIONS:
            raise ValueError(f"Missing manual testing explanation: {case['id']}")
        look, vulnerable, not_report = EXPLANATIONS[case['id']]
        case.setdefault('look_for', look)
        case.setdefault('vulnerable', vulnerable)
        case.setdefault('not_report', not_report)
        case.setdefault('objective', case['procedure'])
    return cases
