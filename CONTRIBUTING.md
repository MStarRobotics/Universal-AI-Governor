# Contributing to Universal AI Governor

We welcome contributions to the Universal AI Governor project! By contributing, you help us build a more secure and robust AI governance platform. Please take a moment to review this guide to ensure a smooth and effective contribution process.

## 1. Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this Code. Please report unacceptable behavior to [morningstar.xcd@gmail.com](mailto:morningstar.xcd@gmail.com).

## 2. How Can I Contribute?

There are many ways to contribute, not just by writing code:

*   **Reporting Bugs**: Identify and report issues to help us improve stability and reliability.
*   **Suggesting Enhancements**: Propose new features or improvements to existing ones.
*   **Writing Documentation**: Improve our guides, API references, and conceptual explanations.
*   **Writing Code**: Implement new features, fix bugs, or improve performance.
*   **Reviewing Pull Requests**: Provide constructive feedback on contributions from others.

## 3. Getting Started

### 3.1. Prerequisites

Ensure you have the following installed:

*   [Rustup](https://rustup.rs/) (for Rust toolchain management)
*   [Go](https://golang.org/doc/install) (version 1.21 or higher)
*   [Docker Desktop](https://www.docker.com/products/docker-desktop) (for containerization and local services)
*   [Homebrew](https://brew.sh/) (macOS) or your system's package manager (Linux) for system dependencies.

### 3.2. Clone the Repository

```bash
git clone https://github.com/morningstarxcdcode/universal-ai-governor.git
cd universal-ai-governor
```

### 3.3. Set Up Your Development Environment

Our `setup.sh` script automates the installation of most development dependencies:

```bash
./scripts/setup.sh
```

This script will:
*   Install `rustfmt` and `clippy` components for Rust.
*   Install system-level dependencies (e.g., `tpm2-tss`, `json-c`) via Homebrew on macOS or `apt-get` on Ubuntu.
*   Initialize Go modules and vendor dependencies.

### 3.4. Running the Project Locally

To run the Governor in development mode with hot-reloading for Rust changes:

```bash
cargo watch -x 'run -- --config config/development.toml'
```

## 4. Code Style and Quality

We maintain high standards for code quality and consistency.

### 4.1. Rust

*   **Formatting**: We use `rustfmt`. Ensure your code is formatted correctly before committing:
    ```bash
    cargo fmt --all
    ```
*   **Linting**: We use `clippy` with strict warnings. Run clippy regularly to catch potential issues:
    ```bash
    cargo clippy --all-targets --all-features -- -D warnings
    ```

### 4.2. Go

*   **Formatting**: We use `gofmt` and `goimports`. These are typically run automatically by your IDE or can be run manually:
    ```bash
    go fmt ./...
    go run golang.org/x/tools/cmd/goimports@latest -w .
    ```
*   **Linting**: We use `golangci-lint`. Install it and run before committing:
    ```bash
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    golangci-lint run
    ```
*   **Module Management**: Keep `go.mod` and `go.sum` clean:
    ```bash
    go mod tidy
    go mod vendor
    ```

## 5. Testing

All contributions should be accompanied by appropriate tests. We have unit, integration, and performance tests.

### 5.1. Running All Tests

```bash
./scripts/test.sh
```

Or run them individually:

*   **Rust Tests**:
    ```bash
    cargo test --all-features --verbose
    ```
*   **Go Tests**:
    ```bash
    go test -v ./...
    ```

### 5.2. Writing Tests

*   **Unit Tests**: Located alongside the code they test. Focus on individual functions/modules.
*   **Integration Tests**: Located in the `tests/` directory. Verify interactions between multiple components.
*   **Benchmarks**: Located in the `benches/` directory (Rust) or `_test.go` files with `Benchmark` prefix (Go). Ensure performance is maintained or improved.

## 6. Pull Request Guidelines

1.  **Fork the Repository**: Start by forking the `universal-ai-governor` repository to your GitHub account.
2.  **Create a New Branch**: Create a new branch for your feature or bug fix:
    ```bash
    git checkout -b feature/your-feature-name
    ```
3.  **Implement Your Changes**: Write your code, tests, and update documentation as necessary.
4.  **Ensure Code Quality**: Run all formatting and linting checks (see Section 4).
5.  **Run Tests**: Ensure all tests pass (see Section 5).
6.  **Commit Your Changes**: Write clear, concise commit messages. Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification if possible.
7.  **Push to Your Fork**: Push your new branch to your forked repository.
8.  **Create a Pull Request**: Open a pull request against the `main` branch of the `universal-ai-governor` repository. Provide a detailed description of your changes and reference any relevant issues.

## 7. Documentation Guidelines

*   **Clarity and Precision**: Ensure documentation is clear, accurate, and easy to understand.
*   **Examples**: Provide code examples where appropriate.
*   **Updates**: Update existing documentation when making code changes that affect functionality or architecture.

## 8. Contact

For any questions or further assistance, please open an issue on the GitHub repository or contact [morningstar.xcd@gmail.com](mailto:morningstar.xcd@gmail.com).