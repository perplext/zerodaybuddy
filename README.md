# ZeroDayBuddy - Bug Bounty Assistant Tool

ZeroDayBuddy is a comprehensive bug bounty assistant tool that streamlines the process of taking on new bounty programs and conducting end-to-end reconnaissance and testing.

## Features

- **Platform Integration**: Connect with popular bug bounty platforms (HackerOne, Bugcrowd) to fetch program details and scope
- **Scoped Project Setup**: Automatically set up a structured project workspace ensuring compliance with program scope
- **Automated Reconnaissance**: Perform initial recon to discover assets and identify "low-hanging fruit" vulnerabilities
- **Assisted Testing**: Tools to help investigate complex vulnerabilities requiring human intuition
- **Proxy Support**: Integration with web security proxies to facilitate manual exploration
- **Report Generation**: Generate professional vulnerability reports for submission

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/zerodaybuddy.git
cd zerodaybuddy

# Build the tool
go build -o zerodaybuddy ./cmd/zerodaybuddy

# Run the tool
./zerodaybuddy --help
```

## Usage

### CLI Mode

```bash
# Initialize ZeroDayBuddy
zerodaybuddy init

# List available bug bounty programs
zerodaybuddy list-programs

# Create a new project for a specific program
zerodaybuddy project create --platform hackerone --program example-program

# Run reconnaissance
zerodaybuddy recon run --project example-program

# Run vulnerability scanning
zerodaybuddy scan run --project example-program

# Generate a report
zerodaybuddy report generate --project example-program
```

### Web Interface

```bash
# Start the web server
zerodaybuddy serve
```

Then open your browser and navigate to `http://localhost:8080`

## Security and Ethics

ZeroDayBuddy is designed with security and ethics in mind:

- Only scan targets that are explicitly in-scope for a bug bounty program
- Never scan domains or systems without proper authorization
- Respect rate limits and program rules
- Store sensitive data securely

## Documentation

- [Usage Guide](./USAGE-GUIDE.md) - Detailed instructions for using ZeroDayBuddy
- [TODO List](./TODO.md) - Planned features and improvements
- [API Documentation](./docs/api) - API reference for developers
- [Architecture](./docs/architecture) - System architecture and design

## License

This project is licensed under the MIT License - see the LICENSE file for details.
