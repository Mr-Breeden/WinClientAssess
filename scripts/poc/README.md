# WCA tester-controlled PoC resources

These are **generic reusable tester-controlled validation resources**. They are not tied to any product, vendor, training application, path, service or port. They ship with the WCA source package and are not copied into an assessment's `reports/` directory.

Guided Review resolves applicable helpers against the WCA tool/source directory and provides candidate-specific build or invocation guidance. The assessment output folder is not the PoC resource location.

Use these resources only on an authorized disposable Windows assessment VM. WCA does not automatically deploy, compile, register, launch, restart, inject or exploit anything. A generated plan or successful marker execution still requires tester interpretation of the relevant trust/privilege boundary.

## Resource principles

- harmless proof markers rather than shells;
- explicit tester compilation/invocation;
- candidate-specific output naming where applicable;
- architecture guidance when reliable target evidence exists;
- SHA-256 / PE-machine verification guidance for compiled helpers;
- no product-specific hard-coded targets.
