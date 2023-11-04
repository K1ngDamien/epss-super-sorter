#!/usr/bin/python3
# EPSS Super Sorter - An EPSS exploitability sorter for multiple CVEs
# A project by K1ngDamien
# v1.0.0
#
# https://github.com/K1ngDamien/epss-super-sorter
# Licensed under GNU GPLv3 Standards.  https://www.gnu.org/licenses/gpl-3.0.en.html


import argparse
import requests
import json
from datetime import datetime
from xml.etree.ElementTree import parse


def main():
    print(r"""
     ______ _____   _____ _____    _____                          _____            _            
    |  ____|  __ \ / ____/ ____|  / ____|                        / ____|          | |           
    | |__  | |__) | (___| (___   | (___  _   _ _ __   ___ _ __  | (___   ___  _ __| |_ ___ _ __ 
    |  __| |  ___/ \___ \\___ \   \___ \| | | | '_ \ / _ \ '__|  \___ \ / _ \| '__| __/ _ \ '__|
    | |____| |     ____) |___) |  ____) | |_| | |_) |  __/ |     ____) | (_) | |  | ||  __/ |   
    |______|_|    |_____/_____/  |_____/ \__,_| .__/ \___|_|    |_____/ \___/|_|   \__\___|_|   
                                              | |                                               
                                              |_|                                               
    
                                        Version 1.0.0
                                    A project by K1ngDamien
    """)

    """A function that creates several arguments that are used by the tool. One of which being the file that is needed
    to parse the list of CVEs into the tool.
    
    Returns:
        args -- Lists the converted argument strings in object form with them assigned as attributes of the namespace.

    """
    def argument_creation():
        parser = argparse.ArgumentParser(
            prog='epss-sorter.py',
            description='A tool to sort several CVEs based on their Exploit Prediction Scoring System (EPSS) score')
        parser.add_argument('filename', type=str, help='the file with CVEs to sort')
        parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
        args = parser.parse_args()
        return args

    """A function to retrieve the CVEs that are to be sorted from a .json or .xml file.
    
    Arguments:
        filename -- Takes the filename from the file provided in the CLI and uses the data in this file.
    
    Returns:
        cve_ids_line -- All the CVEs on a single line separated by commas to make the API call in a different method.

    """
    def collect_cve_list(filename):
        try:
            if filename.endswith('.xml'):
                # This handles the XML file
                tree = parse(filename)
                root = tree.getroot()
                cve_ids = [cve.text for cve in root.findall('.//cve/cve_id')]
            elif filename.endswith('.json'):
                # This handles the JSON file
                with open(filename, 'r') as json_file:
                    data = json.load(json_file)
                cve_ids = [entry['cve_id'] for entry in data['cves']]
            else:
                raise ValueError("Unsupported file format. Supported formats: .xml, .json")

            cve_ids_line = ",".join(cve_ids)
            return cve_ids_line

        except Exception as e:
            print(f"Error: {e}")
            return None

    """A function that sends out the call to the FIRST API to retrieve the EPSS information. The CVE name, the EPSS
    score and the percentile.
    
    Returns:
        response -- Returns the type of response from the First EPSS API, with the right format it will be a 200.

    """
    def retrieve_cve_information():
        url = 'https://api.first.org/data/v1/epss?cve=' + collect_cve_list(argument_creation().filename)
        response = requests.get(url)
        return response

    """A function that goes through the FIRST HTTP response and sorts the data based on the EPSS score and thus the
    likeability of the exploitation of a CVE. When sorted the data is returned in the CLI and in the form of a file
    which is created with the current date and time. The function is then called in the main() to execute.

    """
    def return_cve_information():
        if retrieve_cve_information().status_code == 200:
            data = retrieve_cve_information().json()
            sorted_data = sorted(data['data'], key=lambda x: float(x['epss']), reverse=True)

            for entry in sorted_data:
                print(f"CVE: {entry['cve']}, EPSS: {entry['epss']}, Percentile: {entry['percentile']}")

            current_datetime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            filename = f'sorted_data_{current_datetime}.json'

            with open(filename, 'w') as outfile:
                json.dump({'data': sorted_data}, outfile, indent=4)
            print(f"Sorted data saved to '{filename}'")
        else:
            print(f"Failed to retrieve data. Status code: {retrieve_cve_information().status_code}")

    return_cve_information()


if __name__ == '__main__':
    main()
