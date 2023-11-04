# The EPSS Super Sorter

The EPSS Super Sorter is a tool that sorts CVEs based on their Exploit Prediction Scoring System (EPSS) score. 
When a development team receives a penetration test report or a vulnerability scan report, the amount of CVEs
might be overwhelming and the team does not know where to start. This tool will assist in this thinking process and
will sort the CVEs on their EPSS score. The list that follows as a result will help development teams allocate work in
an organized and prioritized manner for each iteration or sprint.

![execution_example](/images/execution_example.png "Execution Example")

## Getting Started

To install the EPSS Super Sorter, all you have to do is clone the repository. To properly use the tool, follow the steps in "Usage".

```
$ git clone https://github.com/K1ngDamien/epss-super-sorter.git
```

### Prerequisites

To properly use the EPSS Super Sorter all you need is the following dependencies:

* Python 3

## Usage

It's very easy to use the EPSS Super Sorter. All you need is a file that is structured like the .json and .xml example files in the project which is filled with the CVE's you want to sort.

```
{
    "cves": [
        {"cve_id": "CVE-2017-0144"},
        {"cve_id": "CVE-2021-44228"},
        {"cve_id": "CVE-2014-0160"},
        {"cve_id": "CVE-2017-5638"},
        {"cve_id": "CVE-2020-1472"}
    ]
}

```

With the data saved in a .JSON or .XML file, you can then use this file to sort the CVEs and get a good overview of what CVE to tackle and prioritise first.

```
$ python epss-sorter.py example.json
$ ./epss-sorter.py example.xml
```
