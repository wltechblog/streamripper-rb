# Contributing to Streamripper

Thank you for your interest in contributing to Streamripper! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/streamripper-rb.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Install dependencies: `bundle install`

## Development Setup

```bash
# Install dependencies
bundle install

# Run tests
bundle exec rspec

# Run linter
bundle exec rubocop
```

## Code Style

- Follow Ruby conventions and style guide
- Use 2-space indentation
- Write descriptive variable and method names
- Add comments for complex logic
- Keep methods focused and small

## Testing

- Write tests for new features
- Ensure all tests pass: `bundle exec rspec`
- Aim for good test coverage
- Test both happy path and error cases

## Commit Messages

- Use clear, descriptive commit messages
- Start with a verb: "Add", "Fix", "Improve", "Refactor"
- Reference issues when applicable: "Fixes #123"
- Keep commits focused on a single change

## Pull Requests

1. Push your branch to your fork
2. Create a pull request with a clear description
3. Reference any related issues
4. Ensure all tests pass
5. Wait for review and address feedback

## Reporting Issues

- Use GitHub Issues for bug reports
- Include steps to reproduce
- Provide expected vs actual behavior
- Include relevant logs or error messages

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

