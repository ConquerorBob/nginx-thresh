# Third-party notices

thresh itself is MIT licensed. It links the following direct dependencies:

| Crate | Version | License |
| --- | --- | --- |
| chrono | 0.4 | MIT OR Apache-2.0 |
| colored | 2.2 | MPL-2.0 |
| indicatif | 0.17 | MIT |
| regex | 1 | MIT OR Apache-2.0 |

The rest of the dependency graph is recorded in `Cargo.lock`; most of it is MIT or Apache-2.0. `colored` is the one file-level copyleft dependency (MPL-2.0). If you redistribute a compiled binary, keep the MPL-2.0 notice for `colored` available, for example by linking to https://github.com/colored-rs/colored and its license text.
