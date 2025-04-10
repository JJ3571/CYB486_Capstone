import os
import subprocess
import argparse
import sys
from dotenv import load_dotenv
# Make sure you have the correct imports for the GenerativeModel approach
from google import generativeai as genai
# from google.generativeai import types # Not strictly needed for this code
from google.generativeai import GenerationConfig # Correct import
import datetime # For timestamping debug messages

# --- Debug Function ---
def debug_print(message):
    """Prints a timestamped debug message."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[DEBUG {timestamp}] {message}")

# --- Configuration ---
debug_print("Setting global configurations.")
NMAP_DEFAULT_OUTPUT_FILE = "nmap_scan_report.xml" # Default filename
GEMINI_MODEL = "gemini-1.5-flash" # Or other compatible model
debug_print(f"NMAP_DEFAULT_OUTPUT_FILE = {NMAP_DEFAULT_OUTPUT_FILE}")
debug_print(f"GEMINI_MODEL = {GEMINI_MODEL}")


# --- Nmap Scan Function ---
def run_nmap_scan(target, output_filename):
    """
    Runs an nmap vulnerability scan on the target and saves the output to an XML file.
    """
    debug_print(f"Entering run_nmap_scan(target='{target}', output_filename='{output_filename}')")
    print(f"[*] Starting Nmap scan on target: {target}...")
    # -sV: Version detection
    # --script vuln: Run vulnerability scanning scripts
    # -oX: Output in XML format
    nmap_command = ["nmap", "-sV", "--script", "vuln", "-oX", output_filename, target]
    debug_print(f"Nmap command constructed: {' '.join(nmap_command)}")

    try:
        debug_print("Calling subprocess.run...")
        process = subprocess.run(nmap_command,
                                 check=True,         # Raise exception on non-zero exit code
                                 capture_output=True, # Capture stdout/stderr
                                 text=True)           # Decode stdout/stderr as text
        debug_print(f"Subprocess completed. Exit code: {process.returncode}")
        # debug_print(f"Nmap stdout:\n{process.stdout}") # Uncomment if needed, can be long
        # debug_print(f"Nmap stderr:\n{process.stderr}") # Uncomment if needed
        print("[+] Nmap scan completed successfully.")
        print(f"[+] Report saved to: {output_filename}")
        debug_print(f"Exiting run_nmap_scan, returning (True, '{output_filename}')")
        return True, output_filename
    except subprocess.CalledProcessError as e:
        debug_print("Caught subprocess.CalledProcessError.")
        error_message = f"[-] Nmap scan failed with exit code {e.returncode}.\n" \
                        f"[-] Target: {target}\n" \
                        f"[-] Command: {' '.join(nmap_command)}\n" \
                        f"[-] Error Output:\n{e.stderr}"
        print(error_message)
        debug_print(f"Exiting run_nmap_scan, returning (False, 'Error message')")
        return False, error_message
    except FileNotFoundError:
        debug_print("Caught FileNotFoundError (nmap command not found?).")
        error_message = "[-] Error: 'nmap' command not found. Please ensure nmap is installed and in your system's PATH."
        print(error_message)
        debug_print(f"Exiting run_nmap_scan, returning (False, 'Error message')")
        return False, error_message
    except Exception as e:
        debug_print(f"Caught unexpected Exception: {type(e).__name__}")
        error_message = f"[-] An unexpected error occurred during the Nmap scan: {e}"
        print(error_message)
        debug_print(f"Exiting run_nmap_scan, returning (False, 'Error message')")
        return False, error_message


# --- Gemini Analysis Function ---
def analyze_report_with_gemini(api_key, report_content):
    """
    Sends the Nmap report content to Google Gemini for analysis using GenerativeModel.
    """
    debug_print(f"Entering analyze_report_with_gemini(api_key='******', report_content='{len(report_content)} bytes')")
    # Don't print the actual API key or full report content in logs
    print("[*] Sending report to Google Gemini for analysis...")

    # --- Start of the TRY block ---
    try:
        debug_print("Configuring genai...")
        genai.configure(api_key=api_key)
        debug_print("genai configured.")

        # Define the system instruction
        debug_print("Defining system instruction.")
        system_instruction_text = """You are a Cybersecurity expert. You will analyze an Nmap vulnerability scan report (provided in XML format) and provide easy-to-read notes on severe vulnerabilities that need to be addressed. Focus on actionable insights and potential impact. Your main goal is to ensure this is easy to understand for someone who may not be a security expert, without sacrificing important technical details. Structure your response clearly, perhaps grouping findings by host or severity. Highlight the most critical issues first."""

        # Define the user prompt *including* the report content
        debug_print("Defining user prompt text.")
        user_prompt_text = f"""Please analyze the following Nmap vulnerability scan report (in XML format) and provide a summary of severe vulnerabilities as described in the system instructions.

        Nmap Report:
        ```xml
        {report_content}
        """ # <-- Correctly terminated f-string
        debug_print(f"User prompt text defined (length: {len(user_prompt_text)}).")

        # Define generation config
        debug_print("Defining GenerationConfig.")
        generation_config = GenerationConfig(
            response_mime_type="text/plain",
            temperature=0.7 # Example parameter
        )
        debug_print(f"GenerationConfig defined: {generation_config}")


        # Select the model and configure it
        debug_print(f"Creating GenerativeModel instance with model: {GEMINI_MODEL}")
        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL, # Make sure GEMINI_MODEL is defined globally
            system_instruction=system_instruction_text,
            generation_config=generation_config
        )
        debug_print("GenerativeModel instance created.")


        # Generate content
        debug_print("Calling model.generate_content...")
        response = model.generate_content(user_prompt_text) # Pass the combined user prompt
        debug_print("model.generate_content call returned.")

        # Check response content carefully in debug
        try:
            response_text = response.text
            debug_print(f"Analysis received (first 100 chars): {response_text[:100]}...")
            print("[+] Analysis received from Gemini.")
            debug_print("Exiting analyze_report_with_gemini, returning analysis text.")
            return response_text
        except Exception as e:
            # Handle cases where response might not have 'text' or accessing it fails
            # See https://github.com/google-gemini/generative-ai-python/issues/115#issuecomment-1862383489
            # The response might be blocked due to safety settings or other issues.
            debug_print(f"Error accessing response.text: {e}")
            debug_print(f"Full Gemini response object: {response}") # Log the whole object for inspection
            print("[-] Gemini response received but could not extract text (check logs and safety settings).")
            debug_print("Exiting analyze_report_with_gemini, returning None.")
            return None

    # --- Required EXCEPT block ---
    except Exception as e:
        debug_print(f"Caught unexpected Exception in Gemini call: {type(e).__name__}")
        print(f"[-] Error communicating with Google Gemini API: {e}")
        debug_print("Exiting analyze_report_with_gemini, returning None.")
        return None

# --- Main Execution Block (RESTORED AND WITH DEBUGGING) ---

if __name__ == "__main__":
    debug_print("Script execution started in main block.")
    # Load environment variables from .env file
    debug_print("Loading environment variables from .env file...")
    load_dotenv()
    debug_print(".env file loaded (if exists).")

    # Get the API key from environment variables
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        debug_print("GEMINI_API_KEY not found in environment variables!")
        print("[-] Error: GEMINI_API_KEY not found in environment variables.")
        sys.exit(1)
    else:
        debug_print("GEMINI_API_KEY found.")

    # Set up argument parser
    debug_print("Setting up argument parser.")
    parser = argparse.ArgumentParser(description="Nmap Vulnerability Scanner and Report Analyzer")
    parser.add_argument("target", help="Target IP address, hostname, or network range to scan")
    parser.add_argument("-o", "--output", default=NMAP_DEFAULT_OUTPUT_FILE,
                        help=f"Output filename for the Nmap XML report (default: {NMAP_DEFAULT_OUTPUT_FILE})")
    parser.add_argument("--keep-report", action="store_true",
                        help="Keep the Nmap XML report file after analysis.")
    debug_print("Parsing command line arguments...")
    args = parser.parse_args()
    debug_print(f"Arguments parsed: target='{args.target}', output='{args.output}', keep_report={args.keep_report}")


    # Run Nmap scan using the filename from arguments
    debug_print(f"Calling run_nmap_scan with target='{args.target}', output='{args.output}'")
    scan_success, output_file_path_or_error = run_nmap_scan(args.target, args.output) # Use args.output
    debug_print(f"run_nmap_scan returned: scan_success={scan_success}")


    if scan_success:
        debug_print("Nmap scan reported as successful. Proceeding to read report.")
        report_content = None
        try:
            debug_print(f"Attempting to open and read report file: {output_file_path_or_error}")
            # Read the Nmap report content using the correct path
            with open(output_file_path_or_error, "r", encoding='utf-8') as file:
                report_content = file.read()
            debug_print(f"Report file read successfully. Content length: {len(report_content)} bytes.")
            if not report_content:
                debug_print("Report file is empty!")
                print(f"[-] Error: Nmap report file '{output_file_path_or_error}' is empty.")
                sys.exit(1) # Exit if report is empty

        except FileNotFoundError:
            debug_print(f"FileNotFoundError caught when trying to read report: {output_file_path_or_error}")
            print(f"[-] Error: Could not find the Nmap report file '{output_file_path_or_error}'.")
            sys.exit(1)
        except Exception as e:
            debug_print(f"Unexpected Exception caught when reading report: {type(e).__name__} - {e}")
            print(f"[-] Error reading Nmap report file '{output_file_path_or_error}': {e}")
            sys.exit(1)

        if report_content:
            debug_print("Report content loaded. Calling analyze_report_with_gemini...")
            # Analyze the report with Google Gemini
            analysis_result = analyze_report_with_gemini(api_key, report_content)
            debug_print(f"analyze_report_with_gemini returned. Result is None: {analysis_result is None}")
            if analysis_result is not None:
                debug_print(f"Analysis result received (length: {len(analysis_result)}).")

            if analysis_result:
                debug_print("Analysis result is not empty. Printing results.")
                print("\n--- Gemini Vulnerability Analysis ---")
                print(analysis_result)
                print("-------------------------------------\n")
            else:
                debug_print("Analysis result is None or empty. Printing failure message.")
                print("[-] Failed to get analysis from Google Gemini.")
                # Keep the report if analysis failed
                print(f"[*] Nmap report file kept at: {output_file_path_or_error}")
                debug_print("Exiting script due to failed analysis.")
                sys.exit(1) # Exit if analysis failed

        # Cleanup (optional) - Use the correct output file path
        if not args.keep_report:
            debug_print(f"Keep_report flag is False. Attempting to remove report file: {output_file_path_or_error}")
            try:
                os.remove(output_file_path_or_error)
                print(f"[*] Temporary Nmap report file '{output_file_path_or_error}' removed.")
                debug_print("Report file removed successfully.")
            except OSError as e:
                debug_print(f"OSError caught during report file removal: {e}")
                print(f"[-] Warning: Could not remove Nmap report file '{output_file_path_or_error}': {e}")
        else:
            debug_print("Keep_report flag is True. Report file will not be removed.")

    else:
        debug_print("Nmap scan reported as failed. Exiting script.")
        print("[-] Nmap scan failed. Exiting.")
        sys.exit(1) # Exit if scan failed initially

    debug_print("[*] Script finished successfully.")
    print("[*] Script finished.")