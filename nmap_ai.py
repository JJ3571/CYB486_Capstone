import os
import subprocess
import argparse
import sys
import csv 
from dotenv import load_dotenv
from datetime import datetime
import time
from xml.etree import ElementTree as ET  # XML parsing

# Gemini specific imports
from google import generativeai as genai
from google.generativeai import types # Keep this for potential future use, though not strictly needed here
from google.generativeai import GenerationConfig

# --- Config Options ---
NMAP_DEFAULT_OUTPUT_FILE = datetime.now().strftime("nmap_report_%Y%m%d_%H%M%S.xml")  # Default filename if no -o arg in CLI
GEMINI_MODEL = "gemini-1.5-flash"  # Or gemini-2.0-flash, or other compatible model
RESULTS_CSV = "results.csv" # Added CSV tracking to the script

def initialize_csv():
    """Initialize the results.csv file if it doesn't exist."""
    if not os.path.exists(RESULTS_CSV):
        with open(RESULTS_CSV, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["test_id", "file_name", "full_script_duration", "gemini_interpretation_duration",
                             "vulnerability_types", "tokens_used", "false_positives"])
        print(f"[+] Created {RESULTS_CSV} with headers.")

def get_next_test_id():
    # Rolling total of test IDs in the CSV file.
    if not os.path.exists(RESULTS_CSV):
        return 1
    with open(RESULTS_CSV, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        if not rows:
            return 1
        try:
            last_id = int(rows[-1]["test_id"])
            return last_id + 1
        except (ValueError, KeyError):
            # Handle case where header exists but no data rows, or last row is malformed
            print("[-] Warning: Could not parse last test_id from CSV. Starting from 1.")
            return 1


def extract_vulnerability_types(xml_content):
    # This uses xml parsing and pulls the vulnerability types from the XML report, then adds them to results.csv.
    try:
        root = ET.fromstring(xml_content)
        vuln_ids = set()
        # Look for script elements within host/ports/port/script path for more accuracy
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                for script in port.findall('.//script'):
                    if "id" in script.attrib and script.attrib["id"].endswith("-vuln"): # Often vuln scripts end with -vuln
                        vuln_ids.add(script.attrib["id"])
                    elif "output" in script.attrib and "VULNERABLE" in script.attrib["output"].upper(): # Catch generic vuln output
                        vuln_ids.add(script.attrib.get("id", "unknown_vuln_script"))

        # Fallback to searching anywhere if the above finds nothing
        if not vuln_ids:
             for script in root.findall(".//script"):
                if "id" in script.attrib:
                     vuln_ids.add(script.attrib["id"])

        return sorted(list(vuln_ids)) # Return sorted list for consistency
    except ET.ParseError as e:
        print(f"[-] Error parsing XML: {e}")
        return []

def append_to_csv(test_id, script_duration, gemini_duration, vuln_types, tokens_used, file_name):
    with open(RESULTS_CSV, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([test_id, file_name, f"{script_duration:.2f}", f"{gemini_duration:.2f}", 
                         ";".join(vuln_types), tokens_used, ""]) 
    print(f"[+] Appended results to {RESULTS_CSV}.")

def run_nmap_scan(target, output_filename, extra_nmap_options_str=""):
    """
    Runs an nmap vulnerability scan on the target and saves the output to an XML file.
    Automatically adds --unprivileged flag on Windows.
    """
    print(f"[*] Starting Nmap scan on target: {target}...")
    start_time = time.time()  # Start timing Nmap scan
    extra_opts_list = extra_nmap_options_str.split()

    
    # Added -oN for an actual "human-readable" raw output and extra options to pass directly to nmap.
    # Can add -T4 for faster scans but it is a more blunt network scan, requiring a fast and reliable network. Not 'stealthy'
    nmap_command_base = ["nmap"] + extra_opts_list + \
                            ["-sV", "--script", "vuln", "-oX", output_filename, "-oN", raw_output_file]
    # Check if user is on a Windows device
    if sys.platform == "win32":
        print("[i] Detected Windows platform. Using --unprivileged mode.")
        nmap_command = nmap_command_base + ["--unprivileged", target]
        # Use default console encoding on Windows, utf-8 can sometimes cause issues with subprocess
        subproc_encoding_args = {}
    else:
        nmap_command = nmap_command_base + [target]
        subproc_encoding_args = {'encoding': 'utf-8', 'errors': 'ignore'} # Use utf-8 on non-Windows

    print(f"[*] Executing command: {' '.join(nmap_command)}")

    try:
        process = subprocess.run(nmap_command,
                                 check=True,
                                 capture_output=True,
                                 text=True, # Request text mode
                                 **subproc_encoding_args) # Pass encoding args correctly
        scan_duration = time.time() - start_time  # Nmap scan duration
        print(f"[+] Nmap scan completed successfully in {scan_duration:.2f} seconds.")
        print(f"[+] Raw report saved to: {output_filename}")

        # Check if the output file actually exists and has content
        if not os.path.exists(output_filename) or os.path.getsize(output_filename) == 0:
             print(f"[-] Warning: Nmap command finished, but output file '{output_filename}' is missing or empty.")
             # Try to get error output if available
             if process.stderr:
                  print(f"[-] Nmap stderr:\n{process.stderr}")
             return False, f"Nmap command finished, but output file '{output_filename}' is missing or empty.", None


        return True, output_filename, scan_duration
    except subprocess.CalledProcessError as e:
        stderr_decoded = e.stderr or "No stderr captured." # Use captured stderr if available
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
        # Catch potential encoding errors during subprocess run if text=True fails
        error_message = f"[-] An unexpected error occurred during the Nmap scan: {e}"
        print(error_message)
        return False, error_message, None

# Corrected by Gemini to include token counts from api response.
def analyze_report_with_gemini(api_key, report_content):
    """
    Sends the Nmap report content to Google Gemini for analysis using GenerativeModel.

    Args:
        api_key (str): Google Gemini API key.
        report_content (str): The content of the Nmap scan report (XML format).

    Returns:
        tuple: The analysis text generated by Gemini, the analysis duration, and total tokens used.
               Returns (None, None, None) on failure.
    """
    print("[*] Sending report to Google Gemini for analysis...")
    start_time = time.time()  # Start AI analysis timing
    analysis_text = None
    analysis_duration = None
    total_tokens = 0 # Default to 0 tokens

    try:
        genai.configure(api_key=api_key)

        system_instruction_text = """You are a Cybersecurity expert. You will analyze an Nmap vulnerability scan report (provided in XML format) and provide easy-to-read notes on severe vulnerabilities that need to be addressed. Focus only on actionable vulnerabilities and potential impact. Your main goal is to ensure this is easy to understand for someone who may not be a security expert, without sacrificing important technical details. Structure your response clearly, perhaps grouping findings by host or severity. Highlight the most critical issues first."""

        # Gemini models have token limits. This is a basic check.
        MAX_REPORT_LENGTH = 1_000_000
        if len(report_content) > MAX_REPORT_LENGTH:
             print(f"[-] Warning: Report content is very long ({len(report_content)} chars). Truncating to {MAX_REPORT_LENGTH} chars for API call.")
             report_content = report_content[:MAX_REPORT_LENGTH]


        user_prompt_text = f"""Please analyze the following Nmap vulnerability scan report (in XML format) and provide a summary of severe vulnerabilities as described in the system instructions.

Nmap Report:
```xml
{report_content}
```"""

        generation_config = GenerationConfig(
            response_mime_type="text/plain",
            temperature=0.1  # Low temp for consistent results.
        )

        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL,
            system_instruction=system_instruction_text,
            generation_config=generation_config
        )

        response = model.generate_content(user_prompt_text)

        analysis_duration = time.time() - start_time  # Calculate duration immediately after response

        # Check for safety ratings or blocks before accessing text/metadata
        if not response.candidates:
             block_reason = response.prompt_feedback.block_reason if hasattr(response.prompt_feedback, 'block_reason') else 'Unknown'
             print(f"[-] Gemini analysis failed or was blocked. Reason: {block_reason}")
             # Check for safety ratings details if available
             if hasattr(response.prompt_feedback, 'safety_ratings'):
                 print(f"[-] Safety Ratings: {response.prompt_feedback.safety_ratings}")
             return None, analysis_duration, 0 # Return duration but no text/tokens

        # --- Corrected Token Extraction --- (This was done by Gemini, not us.)
        # Check if usage_metadata exists before accessing attributes
        if hasattr(response, 'usage_metadata') and response.usage_metadata:
            usage_metadata = response.usage_metadata
            # Access token counts using attribute notation (.)
            total_tokens = usage_metadata.total_token_count
            prompt_tokens = usage_metadata.prompt_token_count
            # The output tokens are often in candidates_token_count
            output_tokens = usage_metadata.candidates_token_count

            print(f"[+] Analysis received from Gemini in {analysis_duration:.2f} seconds.")
            print(f"[+] Token usage: {total_tokens} tokens (input: {prompt_tokens}, output: {output_tokens})")
        else:
            # Handle cases where metadata might be missing but content exists
            print(f"[+] Analysis received from Gemini in {analysis_duration:.2f} seconds, but token usage metadata was not available.")
            # total_tokens remains 0 as initialized

        # Safely access the response text
        # Sometimes the text might be inside response.candidates[0].content.parts[0].text
        try:
             analysis_text = response.text
        except ValueError as e:
             # This can happen if the response was blocked due to safety settings etc.
             print(f"[-] Could not extract text from Gemini response: {e}")
             # Attempt to get block reason again if not caught earlier
             if not response.candidates:
                 block_reason = response.prompt_feedback.block_reason if hasattr(response.prompt_feedback, 'block_reason') else 'Unknown'
                 print(f"[-] Gemini analysis failed or was blocked. Reason: {block_reason}")
             return None, analysis_duration, total_tokens # Return duration and any tokens counted so far


        return analysis_text, analysis_duration, total_tokens

    except (types.PermissionDenied, genai.types.PermissionDeniedError) as e: 
         print(f"[-] Google Gemini API Error: Permission Denied. Check your API key. Details: {e}")
         analysis_duration = time.time() - start_time if start_time else None
         return None, analysis_duration, 0
    # Catch potential issues with the API call itself (network, config, etc.)
    except Exception as e:
        print(f"[-] Error communicating with Google Gemini API: {e}")
        # Calculate duration
        analysis_duration = time.time() - start_time if start_time else None
        import traceback
        traceback.print_exc() # Print full traceback for debugging
        return None, analysis_duration, 0 # Return None, duration if available, 0 tokens

# Main func
if __name__ == "__main__":
    load_dotenv()
    initialize_csv()
    test_id = get_next_test_id()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[-] Error: GEMINI_API_KEY not found in environment variables.")
        print("[-] Please ensure you have a .env file in the same directory with GEMINI_API_KEY=YOUR_API_KEY")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Nmap Vulnerability Scanner and Report Analyzer")
    parser.add_argument("target", help="Target IP address, hostname, or network range to scan")
    parser.add_argument("-o", "--output",
                        help=f"Base name for output files (e.g., 'my_scan'). _raw.xml and _gemini.txt will be appended. If not provided, defaults based on timestamp.")
    parser.add_argument("--keep-report", action="store_true",
                        help="Keep the raw Nmap XML report file after analysis.")
    parser.add_argument("--nmap-options",
                    help="Additional options to pass directly to Nmap (e.g., '-p 80,443 --top-ports 10')",
                    default="")
    args = parser.parse_args()

    script_start_time = time.time()  # Start full script timing

    # Determine output file names
    if args.output:
        # User provided a base name
        output_base = args.output.replace(".xml", "") # Remove extension if added in cli args
        raw_output_file = f"{output_base}_raw.xml"
        raw_output_file_txt = f"{output_base}_raw.txt"
        gemini_output_file = f"{output_base}_gemini.txt" # Changed to .txt for ease of use
    else:
        # Use default timestamped names
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_output_file = f"nmap_report_{timestamp_str}_raw.xml"
        gemini_output_file = f"nmap_report_{timestamp_str}_gemini.txt" # Changed to .txt

    print(f"[*] Raw Nmap report will be saved to: {raw_output_file}")
    print(f"[*] Gemini analysis will be saved to: {gemini_output_file}")

    scan_success, raw_output_file_path, scan_duration = run_nmap_scan(args.target, raw_output_file)

    if scan_success and raw_output_file_path: # Ensure path is returned
        report_content = None
        try:
            # small delay in case the OS hasn't flushed the file write completely
            time.sleep(0.5)
            with open(raw_output_file_path, "r", encoding='utf-8', errors='ignore') as file: # Add errors='ignore' for robustness
                report_content = file.read()
            if not report_content:
                print(f"[-] Error: Nmap report file '{raw_output_file_path}' is empty after successful scan command.")

        except FileNotFoundError:
            print(f"[-] Error: Could not find the Nmap report file '{raw_output_file_path}' even after scan reported success.")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error reading Nmap report file '{raw_output_file_path}': {e}")
            sys.exit(1)

        # Proceed only if report_content was successfully read
        if report_content:
            vuln_types = extract_vulnerability_types(report_content)
            analysis_result, analysis_duration, tokens_used = analyze_report_with_gemini(api_key, report_content)

            if analysis_result is not None and analysis_duration is not None: # Check both are returned
                print("\n--- Gemini Vulnerability Analysis ---")
                print(analysis_result)
                print("-------------------------------------\n")

                # Save the Gemini report to its own _gemini file
                try:
                    with open(gemini_output_file, "w", encoding='utf-8') as file:
                        file.write(f"--- Gemini Analysis for Nmap Scan on {args.target} ---\n")
                        file.write(f"Analysis Duration: {analysis_duration:.2f} seconds\n")
                        file.write(f"Tokens Used: {tokens_used}\n")
                        file.write("-----------------------------------------------\n\n")
                        file.write(analysis_result)
                    print(f"[+] Finalized Gemini report saved to: {gemini_output_file}")
                except Exception as e:
                     print(f"[-] Error writing Gemini output file '{gemini_output_file}': {e}")

                script_duration = time.time() - script_start_time
                append_to_csv(test_id, script_duration, analysis_duration, vuln_types, tokens_used)
            else:
                print("[-] Failed to get analysis from Google Gemini.")
                print(f"[*] Raw Nmap report file kept at: {raw_output_file_path}")
        else:
             print("[-] Skipping Gemini analysis as Nmap report content could not be read.")


        if not args.keep_report and os.path.exists(raw_output_file_path): # Check existence before removing
            try:
                os.remove(raw_output_file_path)
                print(f"[*] Temporary raw Nmap report file '{raw_output_file_path}' removed.")
            except OSError as e:
                print(f"[-] Warning: Could not remove raw Nmap report file '{raw_output_file_path}': {e}")

    else:
        print(f"[-] Nmap scan failed or did not produce an output file. Review errors above. Exiting.")
        script_duration = time.time() - script_start_time
        print(f"[*] Total script duration before exit: {script_duration:.2f} seconds")
        sys.exit(1)

    # Final script duration print
    script_duration = time.time() - script_start_time
    print(f"\n[+] Full script execution completed in {script_duration:.2f} seconds.")