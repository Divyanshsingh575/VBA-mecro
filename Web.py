import olefile
import zipfile
import re
import streamlit as st
import os
import tempfile

st.markdown(
    """
    <style>
    body {
        background-color: #FFFFFF;
    }
    .title-wrapper > .title {
        color: red;
    }
    </style>
    """,
    unsafe_allow_html=True
)


def accept_and_validate_file(file_path):
    # Validate the chosen file
    valid_extensions = ('.xls', '.xlsm', '.xlsb', '.xlsx', '.docx', '.doc', '.pptx', '.pptm')
    if file_path and file_path.lower(valid_extensions):
        return file_path
    else:
        st.error("Invalid file type selected. Please select a valid Office file.")
        return None


def extract_vba(file_path):
    # Check if the file is an older format (OLE-based) or a newer format (OpenXML)
    valid_extensions = ('.xls', '.xlsm', '.xlsb', '.doc', '.pptm')
    if file_path.name.lower().endswith(valid_extensions):
        if olefile.isOleFile(file_path):
            # It's an OLE file
            ole = olefile.OleFileIO(file_path)
            # Check if it contains VBA code
            if "VBA" in ole.listdir():
                # Path to the VBA project might vary, but typically includes these components
                vba_path = 'VBA/VBAProject.bin'
                if ole.exists(vba_path):
                    vba_data = ole.openstream(vba_path)
                    vba_content = vba_data.read()
                    ole.close()
                    return vba_content
            ole.close()
        else:
            # It's an OpenXML file (OOXML format packed as a Zip archive)
            try:
                with zipfile.ZipFile(file_path) as z:
                    # Paths for VBA projects in different Office file types
                    vba_paths = {
                        '.xlsm': 'xl/vbaProject.bin',
                        '.doc': 'word/vbaProject.bin',
                        '.pptm': 'ppt/vbaProject.bin'
                    }
                    # Get the correct path for the file type
                    file_ext = os.path.splitext(file_path.name)[-1]
                    vba_path = vba_paths.get(file_ext)
                    if vba_path and vba_path in z.namelist():
                        with z.open(vba_path) as f:
                            vba_content = f.read()
                            return vba_content
            except zipfile.BadZipFile:
                print("The file does not seem to be a valid zip file.")
            print("No VBA data found in the OOXML file.")
    elif file_path.name.lower().endswith('.xlsx'):
        print("Regular .xlsx files do not contain macros.")

    return None


# Helper function to update risk score
def update_risk_score(score, points, reason):
    score += points
    print(f"Risk updated by {points} points due to {reason}")
    return score


def check_download_functions(vba_code):
    patterns = ["URLDownloadToFile"]
    risk_score = 0
    for pattern in patterns:
        if re.search(re.escape(pattern), vba_code, re.IGNORECASE):
            risk_score = update_risk_score(risk_score, 25, f"Downloading/executing files using {pattern}")
    return risk_score


def check_shell_functions(vba_code):
    patterns = ["Shell"]
    risk_score = 0
    for pattern in patterns:
        if re.search(re.escape(pattern), vba_code, re.IGNORECASE):
            risk_score = update_risk_score(risk_score, 20, f"Executing system commands using {pattern}")
    return risk_score


def check_file_system_functions(vba_code):
    patterns = ["CreateObject(\"Scripting.FileSystemObject\")", "Kill", "DeleteFile"]
    risk_score = 0
    for pattern in patterns:
        if re.search(re.escape(pattern), vba_code, re.IGNORECASE):
            risk_score = update_risk_score(risk_score, 15, f"Manipulating file system using {pattern}")
    return risk_score


def check_info_gathering_functions(vba_code):
    patterns = ["GetSpecialFolder", "Username"]
    risk_score = 0
    for pattern in patterns:
        if re.search(re.escape(pattern), vba_code, re.IGNORECASE):
            risk_score = update_risk_score(risk_score, 10, f"Gathering information using {pattern}")
    return risk_score


def check_network_functions(vba_code):
    patterns = ["Windsock", "HTTP", "SendKeys"]
    risk_score = 0
    for pattern in patterns:
        if re.search(re.escape(pattern), vba_code, re.IGNORECASE):
            risk_score = update_risk_score(risk_score, 15, f"Network communication using {pattern}")
    return risk_score


def check_environment_functions(vba_code):
    patterns = [
        r"Environ$\"TEMP\"$",  # Retrieving temporary directory
        r"Environ\(\"[^\"]+\"\)",  # Accessing environment variables directly
        r"Environ\(\"ComSpec\"\)",  # Getting system command interpreter path
        r"Environ\(\"SystemRoot\"\)",  # Accessing system directories
        r"Environ\(\"TEMP\"\)",  # Retrieving temporary directory
        r"Environ\(\"TMP\"\)",  # Retrieving temporary directory
        r"Environ\(\"UserProfile\"\)",  # Retrieving user profile directory
        r"Environ\(\"OneDrive\"\)",  # Retrieving OneDrive directory
        r"Environ\(\"OneDriveConsumer\"\)",  # Retrieving OneDrive directory
        r"Environ\(\"OS\"\)",  # Getting operating system information
        r"Environ\(\"PROCESSOR_ARCHITECTURE\"\)",  # Getting processor architecture
        r"Environ\(\"NUMBER_OF_PROCESSORS\"\)",  # Getting number of processors
        r"Environ\(\"DriverData\"\)",  # Retrieving driver data directory
        r"Environ\(\"windier\"\)",  # Getting Windows directory
        r"Environ\(\"USERNAME\"\)",  # Getting username
        r"Environ\(\"ComputerName\"\)",  # Getting computer name
        r"Environ\(\"Path\"\)",  # Accessing system and user-defined paths
        r"Environ\(\"PATH EXT\"\)",  # Getting executable file extensions
        r"Environ\(\"PSModulePath\"\)",  # Getting PowerShell module paths
        r"Environ\(\"PyCharm\"\)",  # Getting PyCharm installation path
        r"Environ\(\"PyCharm Community Edition\"\)",  # Getting PyCharm Community Edition installation path
        r"Environ\(\"VBOX_MSI_INSTALL_PATH\"\)",  # Getting VirtualBox installation path
    ]
    risk_score = 0
    for pattern in patterns:
        if re.search(pattern, vba_code):
            risk_score = update_risk_score(risk_score, 15, f"Accessing environment variable {pattern}")
    return risk_score


def find_readable_strings(binary_data):
    # Attempt to find readable ASCII strings in the binary data
    try:
        # Regex to find sequences of printable characters
        text_segments = re.findall(b'[\\x20-\\x7E]{4,}', binary_data)
        decoded_segments = [segment.decode('ascii') for segment in text_segments]
        return '\n'.join(decoded_segments)
    except Exception as e:
        print(f"Failed to extract readable strings due to: {e}")
        return ""


def parse_vba_content(vba_content):
    if not vba_content:
        print("No VBA content detected. Your file is safe")
        return

    print("VBA content size:", len(vba_content))

    # Extract readable parts from the binary content
    readable_text = find_readable_strings(vba_content)
    if readable_text:
        print("Extracted VBA Code:")
        # Uncomment the next line if you want to print the extracted VBA code
        # print(readable_text)
    else:
        print("No readable VBA code extracted.")

    # Here, apply your risk assessment checks if any readable text is found
    if readable_text:
        total_risk_score = 0
        total_risk_score += check_download_functions(readable_text)
        total_risk_score += check_shell_functions(readable_text)
        total_risk_score += check_file_system_functions(readable_text)
        total_risk_score += check_info_gathering_functions(readable_text)
        total_risk_score += check_network_functions(readable_text)
        total_risk_score += check_environment_functions(readable_text)

        # Calculate the percentage of the risk score
        max_possible_score = 100  # The maximum score if all risks are at their highest
        risk_percentage = (total_risk_score / max_possible_score) * 100

        # Provide detailed feedback based on the risk percentage
        if risk_percentage == 0:
            st.success("The file appears to be safe, with no malicious indicators detected.")
        elif risk_percentage <= 25:
            st.warning("Low risk detected. Be cautious of minor potential threats in the file.")
        elif risk_percentage <= 50:
            st.warning("Moderate risk detected. This file contains elements that could be potentially harmful.")
        elif risk_percentage <= 75:
            st.error("High risk detected. This file likely contains malicious components.")
        else:
            st.error("Very high risk detected. This file is almost certainly harmful and should not be trusted.")

        st.write(f"Total risk score: {total_risk_score} out of {max_possible_score} ({risk_percentage:.2f}%)")


def save_uploaded_file(uploaded_file):
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_file_path = os.path.join(tmp_dir, uploaded_file.name)
        with open(temp_file_path, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        return temp_file_path


def main():
    # Create columns for the color bars
    # Create columns for the color bars
    # Create columns for the color bars
        # Create columns for the color bars
    cols = st.columns(5)
    cols[0].markdown("""<div style="background-color: #e53935; height: 40px; margin-right: -20px;"></div>""", unsafe_allow_html=True)
    cols[1].markdown("""<div style="background-color: #fb8c00; height: 40px; margin-right: -20px;"></div>""", unsafe_allow_html=True)
    cols[2].markdown("""<div style="background-color: #fdd835; height: 40px; margin-right: -20px;"></div>""", unsafe_allow_html=True)
    cols[3].markdown("""<div style="background-color: #39cb7f; height: 40px; margin-right: -20px;"></div>""", unsafe_allow_html=True)
    cols[4].markdown("""<div style="background-color: #42a5f5; height: 40px;"></div>""", unsafe_allow_html=True)

# Get the image data
    import base64

    with open("logo.jpeg", "rb") as f:
        image_data = f.read()

    # Encode the image data in Base64
    image_data_base64 = base64.b64encode(image_data).decode()

    # Display the logo above the title
    st.markdown(
        f'<div style="text-align:center"><img src="data:image/jpeg;base64,{image_data_base64}" width="170"></div>',
        unsafe_allow_html=True)

    # Add the heading
    st.markdown("<h1 style='text-align:center;color:red;'>Worried about macros statues in a received file?</h1>",
                unsafe_allow_html=True)

    # Add the instruction
    # Upload instruction centered
    st.markdown(
        "<p style='text-align:center; font-size: larger;'>Upload the file now and let's analyze it for you!</p>",
        unsafe_allow_html=True)

    # Note centered
    st.markdown("<p style='text-align:center;'><strong style='color:green;'>*Note:</strong> <em><strong>Microsoft Office PowerPoint, Word, and Excel are accepted.</strong></em></p>",
                unsafe_allow_html=True)

    # Read the PNG image from your system

    file_path = st.file_uploader("Select analyze:", type=['xls', 'xlsm', 'xlsb', 'xlsx', 'docx', 'doc', 'pptx', 'pptm'])
    if file_path:
        temp_file_path = save_uploaded_file(file_path)
        vba_content = extract_vba(file_path)
        parse_vba_content(vba_content)


if __name__ == "__main__":
    main()
