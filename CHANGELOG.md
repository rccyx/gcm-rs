# Changelog

## v2.0.1 2025-10-07

### Changes since v2.0.0
- 4be7cbe chore: bump version to 2.0.1
- dfdd5fd update lock
- 2502925 release version 2

### Authors
- rccyx (3 commits)

### Compare
https://github.com/ashgw/gcm-rs/compare/v2.0.0...v2.0.1


## v2.0.0 2025-10-07

### Changes since 274f456b67794f915f66747a464ac4835b9ed870
- 8f2cc6e chore: bump version to 2.0.0
- 0770f59 update readme
- a8950bd fix error & AAD
- 2fd8a97 fix error implementation
- 3742b5a fix build
- 0b98c59 fix zeroize problem
- 7bf12c9 fix ci
- 7140400 cleanup hooks
- c0e4a19 release version 2
- b82b989 fix lint (blcok size)
- 4a5ea7b update aes implementation
- 2f54e43 update types
- 932afe9 update constants
- 081310a chore: release 6 beta
- 7bc8fa9 chore: release 5 beta
- 340913b fix(ci): lint job check() condition
- 6b3fd9f fix: clippy buggin'
- 65f338b chore: beta release
- f8a84e0 chore: yeat cache
- ddf7e67 chore: release v1.0.1
- d760354 refactor: split python & rust packages
- 0452436 fix: email address used for publishing
- 2b254d8 ci: add tests for all major platforms
- 1766122 chore: cleaup unused imports
- fb780bf build: clearup py module
- 493275c fix: build, allow dead code still
- 375247a feat: bind `GCM` intial bindings
- 597db6c feat: bind `gen_key()` & `gen_nonce()`
- c64b017 feat: add `gen_key()` & `gen_nonce()`
- 6ffe32d refactor: move `Aes256Gcm` & `Aes256Ctr32` in `/gcm` & `/ctr`
- 93b150d build: add `maturin`
- f267fae refactor: use `BlockBytes` for sequential buffer
- d90e626 refactor: type conformity
- 1b1901b refactor: add consts crate
- e061ae1 feat: finish gcm implementation
- 23f7d57 ci: add conventional commits
- 5d62e97 ci: add gh workflows
- 40645b5 feat: contain the correct size  `InvalidNonceSize`
- f172024 fix(error.rs): match against all error variations
- 25c7c11 feat(ctr): apply keystream to the data buffer
- 62fd0e4 feat: use  `from_key()`
- e2ba225 refactor: check nonce validity seperately
- 6311fb1 feat: impement `Aes256Ctr32`
- 1dbfd34 feat: impement debug for errors
- 4d2c9fd feat: add errors
- 339c212 feat: add types
- 121ade2 build: add deps & lib confs
- 3d903cf build(pre-commit): add confs
- 69fc27a chore: set max width
- 27829a0 chore: ignore coverage
- 715c4c0 chore: add LICENSE
- 39f0548 build(just): done
- 63403c4 build(ci): conventional commits set
- 69237dd build(ci): hooks done

### Authors
- AshGw (41 commits)
- rccyx (13 commits)

### Compare
https://github.com/ashgw/gcm-rs/compare/274f456b67794f915f66747a464ac4835b9ed870...v2.0.0

