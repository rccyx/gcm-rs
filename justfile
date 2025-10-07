export RUST_BACKTRACE := "1"
alias s:= setup
alias c:= clean
alias f:= format
alias l:= clippy  # l for lint

alias cov:= coverage

@setup:
    # rustup install nightly
    # cargo install cargo-tarpaulin
    rustup component add clippy-preview
    pip install maturin
    maturin build
    just h
    cargo build

@clean:
    rm -rf target  dist  cobertura.xml

@coverage:
    cargo +nightly tarpaulin --verbose --all-features --workspace --timeout 120 --out html


@format:
     cargo fmt

@clippy:
    cargo clippy -- -D warnings -A incomplete_features -W clippy::dbg_macro -W clippy::print_stdout

