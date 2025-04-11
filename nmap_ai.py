import os
import subprocess
import argparse
import sys
from dotenv import load_dotenv
from datetime import datetime
import time

# Gemini specific imports
from google import generativeai as genai
from google.generativeai import types
from google.generativeai import GenerationConfig

# --- Config Options ---
NMAP_DEFAULT_OUTPUT_FILE = datetime.now().strftime("nmap_report_%Y%m%d_%H%M%S.xml")  # Default filename if no -o arg in CLI
GEMINI_MODEL = "gemini-1.5-flash"  # Or gemini-2.0-flash, or other compatible model

def run_nmap_scan(target, output_filename):
    """
    Runs an nmap vulnerability scan on the target and saves the output to an XML file.
    Automatically adds --unprivileged flag on Windows.
    """
    print(f"[*] Starting Nmap scan on target: {target}...")
    start_time = time.time()  # Start timing Nmap scan

    # Base Nmap command parts
    nmap_command_base = ["nmap", "-sV", "--script", "vuln", "-oX", output_filename]

    # Check if user is on a Windows device
    if sys.platform == "win32":
        print("[i] Detected Windows platform. Using --unprivileged mode.")
        nmap_command = nmap_command_base + ["--unprivileged", target]
        subproc_encoding_args = {'encoding': 'utf-8', 'errors': 'ignore'}
    else:
        nmap_command = nmap_command_base + [target]
        subproc_encoding_args = {}

    print(f"[*] Executing command: {' '.join(nmap_command)}")

    try:
        process = subprocess.run(nmap_command,
                                 check=True,
                                 capture_output=True,
                                 text=True,
                                 **subproc_encoding_args)
        scan_duration = time.time() - start_time  # Nmap scan duration
        print(f"[+] Nmap scan completed successfully in {scan_duration:.2f} seconds.")
        print(f"[+] Raw report saved to: {output_filename}")
        return True, output_filename, scan_duration
    except subprocess.CalledProcessError as e:
        stderr_decoded = e.stderr
        error_message = f"[-] Nmap scan failed with exit code {e.returncode}.\n" \
                        f"[-] Target: {target}\n" \
                        f"[-] Command: {' '.join(nmap_command)}\n" \
                        f"[-] Error Output:\n{stderr_decoded}"
        print(error_message)
        return False, error_message, None
    except FileNotFoundError:
        error_message = "[-] Error: 'nmap' command not found. Please ensure nmap is installed and in your system's PATH."
        print(error_message)
        return False, error_message, None
    except Exception as e:
        error_message = f"[-] An unexpected error occurred during the Nmap scan: {e}"
        print(error_message)
        return False, error_message, None


def analyze_report_with_gemini(api_key, report_content):
    """
    Sends the Nmap report content to Google Gemini for analysis using GenerativeModel.

    Args:
        api_key (str): Your Google Gemini API key.
        report_content (str): The content of the Nmap scan report (XML format).

    Returns:
        str: The analysis text generated by Gemini, or None if an error occurred.
    """
    print("[*] Sending report to Google Gemini for analysis...")
    start_time = time.time()  # Start AI analysis timing

    try:
        genai.configure(api_key=api_key)

        system_instruction_text = """You are a Cybersecurity expert. You will analyze an Nmap vulnerability scan report (provided in XML format) and provide easy-to-read notes on severe vulnerabilities that need to be addressed. Focus on actionable insights and potential impact. Your main goal is to ensure this is easy to understand for someone who may not be a security expert, without sacrificing important technical details. Structure your response clearly, perhaps grouping findings by host or severity. Highlight the most critical issues first."""

        user_prompt_text = f"""Please analyze the following Nmap vulnerability scan report (in XML format) and provide a summary of severe vulnerabilities as described in the system instructions.

        Nmap Report:
        ```xml
        {report_content}
        """

        generation_config = GenerationConfig(
            response_mime_type="text/plain",
            temperature=0.1  # Low temp for consistent results. Not 0.0 as that can cause issues with some models.
        )

        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL,
            system_instruction=system_instruction_text,
            generation_config=generation_config
        )

        response = model.generate_content(user_prompt_text)
        analysis_duration = time.time() - start_time  # AI analysis duration
        print(f"[+] Analysis received from Gemini in {analysis_duration:.2f} seconds.")
        return response.text, analysis_duration

    except Exception as e:
        print(f"[-] Error communicating with Google Gemini API: {e}")
        return None, None


# --- Main Execution ---
if __name__ == "__main__":
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[-] Error: GEMINI_API_KEY not found in environment variables.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Nmap Vulnerability Scanner and Report Analyzer")
    parser.add_argument("target", help="Target IP address, hostname, or network range to scan")
    parser.add_argument("-o", "--output", default=NMAP_DEFAULT_OUTPUT_FILE,
                        help=f"Output filename for the Nmap XML report (default: {NMAP_DEFAULT_OUTPUT_FILE})")
    parser.add_argument("--keep-report", action="store_true",
                        help="Keep the Nmap XML report file after analysis.")
    args = parser.parse_args()

    script_start_time = time.time()  # Start full script timing

    # Add _raw and _gemini to output filemnames
    raw_output_file = args.output.replace(".xml", "_raw.xml")
    gemini_output_file = args.output.replace(".xml", "_gemini.xml")

    scan_success, raw_output_file_path, scan_duration = run_nmap_scan(args.target, raw_output_file)

    if scan_success:
        report_content = None
        try:
            with open(raw_output_file_path, "r", encoding='utf-8') as file:
                report_content = file.read()
            if not report_content:
                print(f"[-] Error: Nmap report file '{raw_output_file_path}' is empty.")
                sys.exit(1)

        except FileNotFoundError:
            print(f"[-] Error: Could not find the Nmap report file '{raw_output_file_path}'.")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error reading Nmap report file '{raw_output_file_path}': {e}")
            sys.exit(1)

        if report_content:
            analysis_result, analysis_duration = analyze_report_with_gemini(api_key, report_content)

            if analysis_result:
                print("\n--- Gemini Vulnerability Analysis ---")
                print(analysis_result)
                print("-------------------------------------\n")

                # Save the Gemini report to its own _Gemini file
                with open(gemini_output_file, "w", encoding='utf-8') as file:
                    file.write(analysis_result)
                print(f"[+] Finalized Gemini report saved to: {gemini_output_file}")
            else:
                print("[-] Failed to get analysis from Google Gemini.")
                print(f"[*] Raw Nmap report file kept at: {raw_output_file_path}")
                sys.exit(1)

        if not args.keep_report:
            try:
                os.remove(raw_output_file_path)
                print(f"[*] Temporary raw Nmap report file '{raw_output_file_path}' removed.")
            except OSError as e:
                print(f"[-] Warning: Could not remove raw Nmap report file '{raw_output_file_path}': {e}")

    else:
        print("[-] Nmap scan failed. Exiting.")
        sys.exit(1)

    script_duration = time.time() - script_start_time  # Full script duration
    print(f"[*] Script finished in {script_duration:.2f} seconds.")
    print(f"[*] Nmap scan duration: {scan_duration:.2f} seconds.")
    print(f"[*] Gemini analysis duration: {analysis_duration:.2f} seconds.")