# AICodeScan - Intelligent Code Audit System

CodeGuardian is an intelligent code audit system designed to analyze C code for potential vulnerabilities and provide detailed reports. It leverages both local and AI-based analysis to identify security risks and suggest mitigations.

## Features

- **Local Vulnerability Detection**: Scans code for known vulnerability patterns using regular expressions.
- **AI-Powered Analysis**: Utilizes OpenAI's API to perform in-depth security analysis.
- **Comprehensive Reporting**: Generates detailed reports in JSON and Markdown formats.
- **Visualization**: Provides visual representations of function call graphs and risk distributions.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yangzhongjie/codeguardian.git
   cd codeguardian
   ```

2. **Install dependencies**:
   Ensure you have Python 3.7+ installed. Then, install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up configuration**:
   Update the `core/config.py` file with your OpenAI API key and other configurations.

## Usage

1. **Run the analysis**:
   Use the following command to analyze a C code file:
   ```bash
   python core/analyzer.py path/to/your/code.c
   ```

2. **View reports**:
   After analysis, reports will be generated in the `reports` directory:
   - `safety.json`: Detailed safety analysis report.
   - `summary.md`: Markdown summary of the analysis.
   - `call_graph.gv.png`: Function call graph visualization.
   - `risk_distribution.html`: Risk distribution visualization.

## Configuration

- **OpenAI API Key**: Set your API key in `core/config.py`.
- **Model Selection**: Choose between using a local model or OpenAI's API for analysis.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please contact [your-email@example.com](mailto:your-email@example.com).
