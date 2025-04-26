# SentinelMind: AI-Powered Threat Hunting Engine

SentinelMind is a modern security tool designed to detect anomalies and advanced persistent threats (APTs) from security log files using AI/ML techniques.

*Featuring a sleek, modern dark blue interface optimized for security analysts*

## Features

- Modern, eye-catching dark-themed UI for security professionals
- Anomaly detection in security logs using isolation forest algorithms
- Support for multiple log formats (syslog, JSON, CSV)
- Attack chain correlation to identify sophisticated threats
- Interactive dashboard with visualizations
- Command-line interface for automation

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/SentinelMind.git
cd SentinelMind

# Create and activate virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r sentinelmind/requirements.txt

# Create required directories
mkdir -p models logs
```

## Quick Start

### Running the GUI

```bash
python -m sentinelmind.gui.main
```

### Using the CLI

```bash
# Scan a log file
python -m sentinelmind.cli.main scan path/to/logfile.log

# Train models with new log data
python -m sentinelmind.cli.main train path/to/training_logs/

# Export results to JSON or CSV
python -m sentinelmind.cli.main export results.json

# View system information
python -m sentinelmind.cli.main info
```

## GUI Usage

1. **Dashboard**: View statistics and visualizations of detected anomalies and threats
2. **Scan**: Upload and analyze new log files
3. **Anomalies**: Browse detailed information about detected anomalies
4. **Attack Chains**: View correlated events that may represent attack chains

## Training Models

For optimal results, train the models on your environment's logs:

1. From the GUI: Go to Tools > Train Models, select your training log directory
2. From CLI: `python -m sentinelmind.cli.main train path/to/logs/`

The application comes with sample logs in `sentinelmind/data/sample_logs/` that you can use for initial training.

## Supported Log Formats

- **Syslog**: Standard system logs (auth.log, syslog, etc.)
- **JSON/JSONL**: Structured JSON logs (one per line for JSONL)
- **CSV**: Comma-separated values with headers

## Customization

The application appearance can be modified by editing:
- `sentinelmind/resources/style.qss` - Main stylesheet for the application

## Troubleshooting

### Common Issues

- If encountering "QApplication not defined" or similar import errors, check requirements installation
- If models fail to load, ensure the `models` directory exists and train models first
- For parsing errors, check that your log format is supported

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 